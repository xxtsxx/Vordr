// =============================================================================
// backdrops.hlsl - Vordr Direct3D 11 DirectCompute Procedural Backdrops (cs_5_0)
// -----------------------------------------------------------------------------
// Compiled offline to deterministic DXBC (src/gpu_backdrops.inc) by
// tools/gen_shaders.py using fxc.exe or D3DCompiler_47.dll:
//   /T cs_5_0 /E CSMain /O3 /Gis (stripped of reflection/debug/private blobs)
//
// Outputs static per-pixel (matte BGRA8, (w2_q8 << 16) | w1_q8) basis into
// RWStructuredBuffer<uint2> g_out so the D3D11 compute shader dispatches ONLY
// ONCE per (size, seed, scheme, mode), while 360-degree chromatic color cycling
// runs in < 0.8 ms on CPU SSE2 with zero D3D11 dispatches or readback stalls.
//
// Modes (u_mode, scalar uniform across the entire dispatch):
//   0 : Cut planes      (layered shadowed diagonal folds + under-fold glow)
//   1 : Low-poly neon   (matte Delaunay relief + continuous neon zig-zag seams)
//   2 : Corner mosaic   (anti-aliased equilateral triangle corner dissolve)
//   3 : Crystal rim     (anisotropic crystalline shards + dual-tone rim edges)
//   4 : Guardian sigil  (emissive faceted Vordr sentinel crest + horizon bounce)
//   5 : Cipher rings    (golden-angle concentric cipher-wheel bead arcs)
//   6 : Intaglio print  (banknote guilloche rosettes + copperplate crosshatch)
//   7 : Leaf            (subtle botanical leaf veins fading softly from side)
//   8 : Shadow          (architectural louver chiaroscuro light & cast shadows)
//   9 : Tattoo          (Nordic knotwork & fine-line ornamental filigree margins)
//  10 : Nebula          (subtle cosmic emission clouds & starlight fading from side)
//  11 : Mariusgenser    (flipped Norwegian Fair Isle knit — calm top, yoke base)
//  12 : Matrix          (subtle cascading digital rain glyphs along outer edges)
//  13 : Tron            (receding perspective light-grid floor & horizon glow)
//  14 : Event horizon   (zoomed-in lower-right black hole dome & photon ring)
//  15 : Spiderweb       (ultra-delicate gossamer corner cobweb & tiny dewdrops)
// =============================================================================

cbuffer BackdropCB : register(b0)
{
    uint  u_width;
    uint  u_height;
    uint  u_seed0;
    uint  u_seed1;

    uint  u_col_bg;       // COLORREF 0x00BBGGRR
    uint  u_col_panel;    // COLORREF 0x00BBGGRR
    uint  u_col_acc;      // COLORREF 0x00BBGGRR
    uint  u_col_acc2;     // COLORREF 0x00BBGGRR

    uint  u_mode;         // 0..22 procedural GPU style
    uint  u_dark;         // 1 = dark scheme, 0 = light scheme
    uint  u_pad0;
    uint  u_pad1;
};

RWStructuredBuffer<uint2> g_out : register(u0);

float3 unpack_colorref(uint c)
{
    return float3(
        float(c & 0xFFu),
        float((c >> 8) & 0xFFu),
        float((c >> 16) & 0xFFu)
    ) * (1.0 / 255.0);
}

uint pack_bgra8(float3 rgb)
{
    uint3 q = uint3(saturate(rgb) * 255.0 + 0.5);
    return 0xFF000000u | (q.r << 16) | (q.g << 8) | q.b;
}

uint pack_weights_q8(float w1, float w2)
{
    uint q1 = min(4095u, uint(max(0.0, w1) * 256.0 + 0.5));
    uint q2 = min(4095u, uint(max(0.0, w2) * 256.0 + 0.5));
    return q1 | (q2 << 16);
}

float hash12(float2 p)
{
    float3 p3 = frac(float3(p.xyx) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return frac((p3.x + p3.y) * p3.z);
}

float2 hash22(float2 p)
{
    float3 p3 = frac(float3(p.xyx) * float3(0.1031, 0.1030, 0.0973));
    p3 += dot(p3, p3.yzx + 33.33);
    return frac((p3.xx + p3.yz) * p3.zy);
}

float seed_unit(uint idx)
{
    uint x = u_seed0 ^ (idx * 0x9E3779B9u) ^ ((u_seed1 << (idx & 7u)) | (u_seed1 >> (32u - (idx & 7u))));
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return float(x & 0xFFFFu) * (1.0 / 65535.0);
}

float seam_side_a(float2 cellCenter, float s0)
{
    return cellCenter.y - (2.35 + 0.55 * sin(cellCenter.x * 0.85 + s0 * 6.28318));
}

float seam_side_b(float2 cellCenter, float s1)
{
    return cellCenter.y - (4.85 + 0.50 * cos(cellCenter.x * 0.78 - s1 * 6.28318));
}

float sd_triangle(float2 p, float2 p0, float2 p1, float2 p2)
{
    float2 e0 = p1 - p0, e1 = p2 - p1, e2 = p0 - p2;
    float2 v0 = p  - p0, v1 = p  - p1, v2 = p  - p2;
    float2 pq0 = v0 - e0 * saturate(dot(v0, e0) / dot(e0, e0));
    float2 pq1 = v1 - e1 * saturate(dot(v1, e1) / dot(e1, e1));
    float2 pq2 = v2 - e2 * saturate(dot(v2, e2) / dot(e2, e2));
    float s = sign(e0.x * e2.y - e0.y * e2.x);
    float2 d = min(min(float2(dot(pq0, pq0), s * (v0.x * e0.y - v0.y * e0.x)),
                       float2(dot(pq1, pq1), s * (v1.x * e1.y - v1.y * e1.x))),
                       float2(dot(pq2, pq2), s * (v2.x * e2.y - v2.y * e2.x)));
    return -sqrt(d.x) * sign(d.y);
}

float vnoise(float2 p)
{
    float2 i = floor(p);
    float2 f = frac(p);
    float2 u = f * f * f * (f * (f * 6.0 - 15.0) + 10.0);
    float a = hash12(i);
    float b = hash12(i + float2(1.0, 0.0));
    float c = hash12(i + float2(0.0, 1.0));
    float d = hash12(i + float2(1.0, 1.0));
    return lerp(lerp(a, b, u.x), lerp(c, d, u.x), u.y);
}

float fbm4(float2 p)
{
    float s = 0.0;
    float a = 0.5;
    float2x2 rot = float2x2(0.80, -0.60, 0.60, 0.80);
    [unroll]
    for (int k = 0; k < 4; k++)
    {
        s += a * vnoise(p);
        p = mul(rot, p) * 2.03 + float2(17.1, 31.7);
        a *= 0.5;
    }
    return s;
}

float sd_seg(float2 p, float2 a, float2 b)
{
    float2 pa = p - a, ba = b - a;
    float h = saturate(dot(pa, ba) / max(dot(ba, ba), 1e-6));
    return length(pa - ba * h);
}

// Returns float4(local.xy, cellId.xy) in pointy-top hex space (edge dist = 0.5 - hex_dist(local))
float4 hex_cell(float2 p)
{
    const float2 r = float2(1.0, 1.7320508);
    const float2 h = r * 0.5;
    float2 a = p - r * floor(p / r) - h;
    float2 b = (p - h) - r * floor((p - h) / r) - h;
    float2 gv = (dot(a, a) < dot(b, b)) ? a : b;
    float2 id = p - gv;
    return float4(gv, id);
}

float hex_dist(float2 q)
{
    q = abs(q);
    return max(dot(q, normalize(float2(1.0, 1.7320508))), q.x);
}

// 2-pass exact Voronoi edge distance: returns float3(edgeDist, centerDist, cellHash)
float3 voronoi_edge(float2 p, float jitter)
{
    float2 n = floor(p);
    float2 f = frac(p);
    float2 mr = float2(0.0, 0.0);
    float2 mg = float2(0.0, 0.0);
    float md = 8.0;
    [loop]
    for (int j = -1; j <= 1; j++)
    {
        [loop]
        for (int i = -1; i <= 1; i++)
        {
            float2 g = float2(float(i), float(j));
            float2 o = lerp(float2(0.5, 0.5), hash22(n + g), jitter);
            float2 r = g + o - f;
            float d = dot(r, r);
            if (d < md)
            {
                md = d;
                mr = r;
                mg = g;
            }
        }
    }
    float ed = 8.0;
    [loop]
    for (int j2 = -1; j2 <= 1; j2++)
    {
        [loop]
        for (int i2 = -1; i2 <= 1; i2++)
        {
            float2 g = mg + float2(float(i2), float(j2));
            float2 o = lerp(float2(0.5, 0.5), hash22(n + g), jitter);
            float2 r = g + o - f;
            float2 diff = r - mr;
            if (dot(diff, diff) > 1e-5)
                ed = min(ed, dot(0.5 * (mr + r), normalize(diff)));
        }
    }
    return float3(ed, sqrt(md), hash12(n + mg));
}

[numthreads(16, 16, 1)]
void CSMain(uint3 dtid : SV_DispatchThreadID)
{
    if (dtid.x >= u_width || dtid.y >= u_height)
        return;

    float invH   = 1.0 / max(1.0, float(u_height));
    float aspect = float(u_width) * invH;
    float2 uv    = (float2(dtid.xy) + 0.5) / float2(max(1u, u_width), max(1u, u_height));
    float2 p     = float2((uv.x - 0.60) * aspect, uv.y - 0.50);
    float2 keyL  = float2((0.78 - 0.60) * aspect, 0.22 - 0.50);

    float3 bg    = unpack_colorref(u_col_bg);
    float3 panel = unpack_colorref(u_col_panel);

    bool isDark  = (u_dark != 0u);
    float spot   = exp(-length(p - keyL) * 1.95);
    float leftGlow = exp(-length(float2((uv.x - 0.18) * aspect, uv.y - 0.34)) * 2.35);
    float s0     = seed_unit(0u);
    float s1     = seed_unit(1u);
    float2 seedVec = float2(s0 * 13.7, s1 * 19.3);

    float3 matte = bg;
    float  w1    = 0.0;
    float  w2    = 0.0;

    [branch]
    switch (u_mode)
    {
    // =========================================================================
    // 0: Cut planes (layered shadowed diagonal folds + under-fold glow)
    // =========================================================================
    default:
    case 0u:
    {
        static const float BASE_ANG[7] = { -0.41, 0.31, -0.96, 0.58, 2.12, -2.56, 1.09 };
        static const float BASE_OFF[7] = { -0.22, 0.14, -0.08, -0.16, 0.09, -0.19, 0.21 };

        matte = lerp(bg, panel, saturate(0.18 + 0.22 * (0.5 - uv.y) + 0.12 * uv.x));

        [loop]
        for (uint i = 0u; i < 7u; i++)
        {
            float jAng = (seed_unit(i * 2u) - 0.5) * 0.22;
            float jOff = (seed_unit(i * 2u + 1u) - 0.5) * 0.11;
            float ang  = BASE_ANG[i] + jAng;
            float2 n   = float2(cos(ang), sin(ang));
            float2 t   = float2(-n.y, n.x);

            float sd    = dot(p, n) - (BASE_OFF[i] + jOff);
            float along = dot(p, t);
            float aa    = invH * 1.15;
            float over  = smoothstep(-aa, aa, sd);
            float underDist = max(0.0, -sd);

            float crease   = exp(-underDist * 82.0) * (1.0 - over);
            float penumbra = exp(-underDist * 11.5) * (1.0 - over);
            float shade    = isDark ? (1.0 - crease * 0.46 - penumbra * 0.25)
                                    : (1.0 - crease * 0.15 - penumbra * 0.085);
            matte *= shade;
            w1    *= shade;
            w2    *= shade;

            if (i == 1u || i == 2u || i == 4u || i == 5u)
            {
                float center    = (seed_unit(i + 20u) - 0.5) * 0.35;
                float lateral   = exp(-pow((along - center) * 1.95, 2.0));
                float bleed     = exp(-underDist * 6.8) * lateral * (1.0 - over);
                float intensity = (isDark ? 0.44 : 0.25) + 0.16 * spot;
                float aGlow     = saturate(bleed * intensity);
                float addGlow   = isDark ? (bleed * intensity * 0.26) : 0.0;
                matte *= (1.0 - aGlow);
                w1    *= (1.0 - aGlow);
                w2    *= (1.0 - aGlow);
                if ((i & 1u) != 0u)
                    w2 += aGlow + addGlow;
                else
                    w1 += aGlow + addGlow;
            }

            float planeStep = 0.12 + 0.09 * float(i % 3u);
            float3 sheetBase = lerp(bg, panel, planeStep);
            float sheetGrad  = dot(p - keyL * 0.35, n) * 0.14 + spot * 0.035;
            float3 sheetCol  = sheetBase + (isDark ? sheetGrad * 0.16 : -sheetGrad * 0.08);
            float ov = over * 0.68;
            matte = lerp(matte, sheetCol, ov);
            w1   *= (1.0 - ov);
            w2   *= (1.0 - ov);

            float rim = exp(-abs(sd) / max(aa * 1.25, 0.0005));
            float rimLight = (0.042 + 0.055 * spot) * (0.5 + 0.5 * saturate(dot(normalize(keyL - p + 0.001), n)));
            float rl = rim * rimLight;
            matte += (isDark ? float3(1.0, 1.0, 1.0) : panel) * (0.38 * rl);
            if ((i & 1u) != 0u)
                w1 += 0.62 * rl;
            else
                w2 += 0.62 * rl;
        }
        break;
    }

    // =========================================================================
    // 1: Low-poly neon (matte Delaunay relief + continuous neon seams)
    // =========================================================================
    case 1u:
    {
        float scale = 6.4;
        float2 gp = float2(uv.x * aspect, uv.y) * scale + float2(s0 * 2.0, 0.0);
        float2 ip = floor(gp);
        float2 fp = frac(gp);

        float md1 = 16.0;
        float2 mr1 = float2(0.0, 0.0);
        float2 id1 = float2(0.0, 0.0);
        float2 pt1 = float2(0.0, 0.0);
        [loop]
        for (int j = -1; j <= 1; j++)
        {
            [loop]
            for (int i = -1; i <= 1; i++)
            {
                float2 g = float2(float(i), float(j));
                float2 o = 0.16 + 0.68 * hash22(ip + g + seedVec);
                float2 r = g + o - fp;
                float d  = dot(r, r);
                if (d < md1)
                {
                    md1 = d;
                    mr1 = r;
                    id1 = ip + g;
                    pt1 = ip + g + o;
                }
            }
        }

        float edgeDist = 16.0;
        float seamA = 0.0;
        float seamB = 0.0;
        float sgn1A = seam_side_a(pt1, s0);
        float sgn1B = seam_side_b(pt1, s1);

        [loop]
        for (int j2 = -2; j2 <= 2; j2++)
        {
            [loop]
            for (int i2 = -2; i2 <= 2; i2++)
            {
                float2 g  = float2(float(i2), float(j2));
                float2 id = ip + g;
                float2 o  = 0.16 + 0.68 * hash22(id + seedVec);
                float2 r  = g + o - fp;
                float2 diff = r - mr1;
                float lenDiff = length(diff);
                if (lenDiff > 0.0001)
                {
                    float ed = dot(0.5 * (mr1 + r), diff / lenDiff);
                    if (ed < edgeDist)
                        edgeDist = ed;

                    float2 pt2 = id + o;
                    if ((sgn1A > 0.0) != (seam_side_a(pt2, s0) > 0.0))
                    {
                        float winA = exp(-pow((uv.x - 0.52) * 1.65, 2.0));
                        seamA = max(seamA, (exp(-ed * 62.0) * 1.15 + exp(-ed * 11.0) * 0.34) * winA);
                    }
                    if ((sgn1B > 0.0) != (seam_side_b(pt2, s1) > 0.0))
                    {
                        float winB = exp(-pow((uv.x - 0.58) * 1.55, 2.0));
                        seamB = max(seamB, (exp(-ed * 62.0) * 1.10 + exp(-ed * 11.0) * 0.32) * winB);
                    }
                }
            }
        }

        float2 n2 = (hash22(id1 * 1.7 + seedVec) - 0.5) * 1.35;
        float3 facetN = normalize(float3(n2, 1.15));
        float3 lightDir = normalize(float3(keyL - p, 0.65));
        float diffL = saturate(dot(facetN, lightDir));

        float3 baseWall = lerp(bg, panel, isDark ? 0.32 : 0.45);
        matte = baseWall * (isDark ? (0.76 + 0.42 * diffL) : (0.91 + 0.14 * diffL));

        float aa = scale * invH * 1.15;
        float groove = 1.0 - smoothstep(0.0, aa * 1.6, edgeDist);
        matte *= isDark ? (1.0 - groove * 0.48) : (1.0 - groove * 0.18);

        float lip = exp(-edgeDist / max(aa * 1.5, 0.001)) * spot * (isDark ? 0.07 : 0.04);
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (lip + pow(saturate(seamA), 3.0) * 0.30 + pow(saturate(seamB), 3.0) * 0.25);
            w1 = seamA * 0.95;
            w2 = seamB * 0.90;
        }
        else
        {
            float aA = saturate(seamA * 0.78);
            float aB = saturate(seamB * 0.72);
            float kAB = (1.0 - aA) * (1.0 - aB);
            matte *= kAB;
            w1 = lip * kAB + aA * (1.0 - aB);
            w2 = aB;
        }
        break;
    }

    // =========================================================================
    // 2: Corner mosaic (anti-aliased equilateral triangle dissolve)
    // =========================================================================
    case 2u:
    {
        float scale = 17.5;
        float2 q = float2(uv.x * aspect, uv.y) * scale;
        float2 sk = float2(q.x + q.y * 0.57735027, q.y * 1.15470054);
        float2 ti = floor(sk);
        float2 tf = frac(sk);
        float upper = step(1.0, tf.x + tf.y);
        float2 triId = float2(ti.x * 2.0 + upper, ti.y);
        float h = hash12(triId + seedVec);

        float dEdge = upper > 0.5
            ? min(min(1.0 - tf.x, 1.0 - tf.y), (tf.x + tf.y - 1.0) * 0.7071)
            : min(min(tf.x, tf.y), (1.0 - tf.x - tf.y) * 0.7071);
        float seam = smoothstep(0.0, scale * invH * 1.3, dEdge);

        float dTR = length(float2((1.0 - uv.x) * aspect * 0.85, uv.y));
        float dBR = length(float2((1.0 - uv.x) * aspect * 0.95, (1.0 - uv.y) * 1.15));
        float dTL = length(float2(uv.x * aspect * 0.95, uv.y * 1.02));
        float field = max(max(1.05 - dTR * 1.08, (0.92 - dBR * 1.25) * 0.85), (0.88 - dTL * 1.18) * 0.82);

        float cellOn = smoothstep(0.22, 0.58, field + (h - 0.5) * 0.52);
        float tMix   = frac(h * 3.17 + uv.y * 0.35);
        float fk     = saturate(isDark ? (0.58 + 0.35 * field) : (0.48 + 0.40 * field));

        float3 baseCanvas = lerp(bg, panel, 0.16 * (1.0 - uv.y));
        float alpha = cellOn * (isDark ? (0.16 + 0.36 * h * saturate(field)) : (0.13 + 0.30 * h * saturate(field)));
        float a = saturate(alpha * (0.78 + 0.22 * seam));
        matte = lerp(baseCanvas, panel * (1.0 - fk), a);
        w1 = a * fk * (1.0 - tMix);
        w2 = a * fk * tMix;
        break;
    }

    // =========================================================================
    // 3: Crystal rim (anisotropic crystalline shards + rim highlights)
    // =========================================================================
    case 3u:
    {
        float2 sp = float2(uv.x * aspect, uv.y);
        float bend = 0.22 * sin(sp.y * 2.1 + s0 * 4.0);
        float2 cr = float2((sp.x + bend) * 7.5 - sp.y * 3.8, sp.y * 11.0 + sp.x * 2.4) + seedVec;

        float2 ci = floor(cr);
        float2 cf = frac(cr);
        float diag = cf.x - cf.y;
        float h = hash12(ci + step(0.0, diag) * 19.1);

        float dDiag = abs(diag) * 0.7071;
        float dCell = min(min(cf.x, 1.0 - cf.x), min(cf.y, 1.0 - cf.y));
        float dEdge = min(dDiag, dCell);

        float perim = smoothstep(0.12, 0.78, (uv.x - 0.25) * 0.78 + uv.y * 0.38 + (h - 0.5) * 0.22);

        float shardSlope = (diag > 0.0 ? (1.0 - cf.x) : (1.0 - cf.y));
        matte = lerp(bg, panel, (0.14 + 0.38 * shardSlope * h) * perim);
        float aa = 9.0 * invH;
        float rimWire = exp(-dEdge / max(aa * 1.35, 0.001)) * perim;
        float crest   = pow(saturate(shardSlope), 3.0) * h * perim;
        float tMix    = smoothstep(0.25, 0.85, uv.x * 0.6 + (1.0 - uv.y) * 0.4);

        if (isDark)
        {
            float rw = rimWire * 0.58 + crest * 0.34;
            matte += float3(1.0, 1.0, 1.0) * rimWire * crest * 0.28;
            w1 = rw * (1.0 - tMix);
            w2 = rw * tMix;
        }
        else
        {
            float a = saturate(rimWire * 0.42 + crest * 0.24);
            matte *= (1.0 - a);
            w1 = a * (1.0 - tMix);
            w2 = a * tMix;
        }
        break;
    }

    // =========================================================================
    // 4: Guardian sigil (emissive low-poly Vordr sentinel crest + horizon)
    // =========================================================================
    case 4u:
    {
        float horizonY = 0.76;
        float floorFade = smoothstep(horizonY - 0.03, 1.0, uv.y);
        matte = lerp(bg, panel, 0.14 * (1.0 - uv.y) + 0.22 * floorFade);

        float2 gc = float2((uv.x - 0.73) * aspect, uv.y - 0.56) * 2.55;
        float2 sym = float2(abs(gc.x), gc.y);
        float aa = invH * 3.0;

        float dCrown = sd_triangle(sym, float2(0.0, -0.44), float2(0.24, -0.10), float2(0.0, 0.10));
        float dEar   = sd_triangle(sym, float2(0.09, -0.24), float2(0.34, -0.52 - 0.06 * s0), float2(0.32, -0.06));
        float dCheek = sd_triangle(sym, float2(0.0, 0.06), float2(0.36, -0.08), float2(0.20, 0.28));
        float dJaw   = sd_triangle(sym, float2(0.0, 0.04), float2(0.21, 0.26), float2(0.0, 0.48));
        float dWing  = sd_triangle(sym, float2(0.22, 0.02), float2(0.46 + 0.05 * s1, 0.14), float2(0.18, 0.34));

        float dUnion = min(min(min(dCrown, dEar), min(dCheek, dJaw)), dWing);
        float dFacet = min(min(min(abs(dCrown), abs(dEar)), min(abs(dCheek), abs(dJaw))), min(abs(dWing), abs(gc.x)));

        float aura = exp(-max(0.0, dUnion) * 4.8);
        float bounce = exp(-pow((uv.x - 0.73) * 3.6, 2.0)) * exp(-abs(uv.y - (horizonY + 0.05)) * 9.5);
        float tg = saturate(0.5 + gc.y);

        if (isDark)
        {
            float gw = aura * 0.24 + bounce * 0.36;
            w1 = gw * (1.0 - tg);
            w2 = gw * tg + leftGlow * 0.14;
        }
        else
        {
            float gw = aura * 0.16 + bounce * 0.22;
            float lg = leftGlow * 0.10;
            float tot = max(gw + lg, 0.0001);
            float a = saturate(gw + lg);
            matte *= (1.0 - a);
            w1 = a * (gw * (1.0 - tg)) / tot;
            w2 = a * (gw * tg + lg) / tot;
        }

        float mask = 1.0 - smoothstep(-aa, aa, dUnion);
        if (mask > 0.001)
        {
            float fId = (dCrown < 0.0 ? 0.18 : 0.0) + (dEar < 0.0 ? 0.34 : 0.0)
                      + (dCheek < 0.0 ? 0.52 : 0.0) + (dJaw < 0.0 ? 0.71 : 0.0)
                      + (gc.x > 0.0 ? 0.11 : -0.07);
            float tf = saturate(fId);
            float fk = saturate(isDark ? (0.64 + 0.26 * (0.5 - gc.y)) : (0.50 + 0.28 * (0.5 - gc.y)));
            float seam = exp(-dFacet / max(aa * 1.15, 0.002));
            float3 fMatte = panel * (1.0 - fk) + (isDark ? float3(1.0, 1.0, 1.0) * (0.36 * seam) : float3(0.0, 0.0, 0.0));
            float fw1 = fk * (1.0 - tf) + (isDark ? 0.0 : 0.22 * seam);
            float fw2 = fk * tf;
            float ma  = mask * (isDark ? 0.74 : 0.58);
            matte = lerp(matte, fMatte, ma);
            w1    = lerp(w1, fw1, ma);
            w2    = lerp(w2, fw2, ma);
        }
        break;
    }

    // =========================================================================
    // 5: Cipher rings (golden-angle concentric cipher-wheel bead arcs)
    // =========================================================================
    case 5u:
    {
        matte = lerp(bg, panel, 0.16 * spot + 0.06 * (1.0 - uv.y));

        float2 cp = float2((uv.x - 0.71) * aspect, uv.y - 0.56);
        float rad = length(cp);
        float ang = atan2(cp.y, cp.x);

        float ringScale = 19.0;
        float rIdx = clamp(floor(rad * ringScale + 0.5), 1.0, 14.0);
        float rCenter = rIdx / ringScale;
        float dr = (rad - rCenter) * ringScale;

        float nBeads = floor(10.0 + rIdx * 6.0);
        float phase  = rIdx * 2.3999632 + s0 * 6.28318;
        float cellA  = (ang + 3.14159265 + phase) / 6.2831853 * nBeads;
        float bIdx   = floor(cellA);
        float da     = (frac(cellA) - 0.5) * (6.2831853 * rCenter * ringScale / nBeads);

        float sectorHash = hash12(float2(rIdx, floor(bIdx * 0.25) + s1 * 17.0));
        float calmEnv = smoothstep(0.10, 0.54, uv.y) * smoothstep(0.24, 0.52, uv.x);
        float beadOn = step(0.34, sectorHash) * smoothstep(14.5, 11.2, rIdx) * step(1.5, rIdx) * calmEnv;

        float beadDist = length(float2(dr, da));
        float aa = ringScale * invH * 1.25;
        float beadCore = (1.0 - smoothstep(0.23 - aa, 0.23 + aa, beadDist)) * beadOn;
        float beadGlow = exp(-beadDist * 5.6) * beadOn * 0.20;
        float guideArc = exp(-abs(dr) * 14.0) * step(1.5, rIdx) * smoothstep(14.5, 11.0, rIdx) * calmEnv * 0.10;
        float tr = frac(rIdx * 0.21 + s0);

        if (isDark)
        {
            float rw = beadCore * 0.48 + beadGlow + guideArc;
            matte += float3(1.0, 1.0, 1.0) * (beadCore * 0.14);
            w1 = rw * (1.0 - tr);
            w2 = rw * tr + leftGlow * 0.13;
        }
        else
        {
            float rw = beadCore * 0.42 + beadGlow * 0.55 + guideArc;
            float lg = leftGlow * 0.09;
            float tot = max(rw + lg, 0.0001);
            float a = saturate(rw + lg);
            matte *= (1.0 - a);
            w1 = a * (rw * (1.0 - tr)) / tot;
            w2 = a * (rw * tr + lg) / tot;
        }
        break;
    }

    // =========================================================================
    // 6: Intaglio print (banknote guilloche rosettes + copperplate engraving)
    // =========================================================================
    case 6u:
    {
        float2 sp = float2((uv.x - 0.5) * aspect, uv.y - 0.5);
        float px = invH;

        // Sweeping multi-phase security banknote guilloche wave ribbons
        float rib = 0.0;
        [unroll]
        for (uint k = 0u; k < 5u; k++)
        {
            float fk = float(k);
            float freq = 5.2 + fk * 1.15;
            float ph = (s0 + fk * 0.19) * 6.28318;
            float env = 0.11 * sin(sp.x * 2.4 + fk * 1.3 + s1 * 4.0)
                      + 0.055 * cos(sp.x * 5.8 - fk * 0.9);
            float yWave = sp.y + env + (fk - 2.0) * 0.065;
            float lineF = sin((yWave * 36.0 + 0.45 * sin(sp.x * freq + ph)) * 3.14159);
            float ridge = 1.0 - smoothstep(0.0, 0.34, abs(lineF));
            float bandMask = exp(-pow((yWave - 0.04 * sin(sp.x * 3.0)) * 3.4, 2.0));
            rib = max(rib, ridge * bandMask * (0.55 + 0.10 * fk));
        }

        // Dual lathe-turned intaglio guilloche rosettes (lower-right & upper-left)
        float2 c1 = float2(0.42 * aspect, 0.34);
        float2 c2 = float2(-0.36 * aspect, -0.32);
        float ros = 0.0;
        [unroll]
        for (uint r = 0u; r < 2u; r++)
        {
            float2 q = (r == 0u) ? (sp - c1) : (sp - c2);
            float rad = length(q);
            float ang = atan2(q.y, q.x) + s0 * 3.14159;
            float petals = (r == 0u) ? 16.0 : 12.0;
            float modR = rad + 0.032 * sin(ang * petals) + 0.014 * cos(ang * (petals * 2.0) + 0.8);
            float rings = 1.0 - smoothstep(0.0, 0.36, abs(sin(modR * 96.0)));
            float rings2 = 1.0 - smoothstep(0.0, 0.36, abs(sin((rad - 0.028 * sin(ang * petals)) * 96.0)));
            float disc = smoothstep(0.56, 0.24, rad) * smoothstep(0.03, 0.10, rad);
            float rGain = (r == 0u) ? 1.0 : 0.55;
            ros = max(ros, max(rings, rings2 * 0.85) * disc * rGain);
        }

        // Fine copperplate diagonal burin crosshatching
        float h1 = 0.5 + 0.5 * sin((sp.x * 0.82 + sp.y * 0.57) * 280.0);
        float h2 = 0.5 + 0.5 * sin((sp.x * 0.57 - sp.y * 0.82) * 240.0);
        float hatch = smoothstep(0.75, 0.98, h1) * 0.55 + smoothstep(0.82, 0.99, h2) * 0.30;
        float vignette = saturate(1.0 - length(sp) * 0.55);

        matte = lerp(bg, panel, saturate(0.20 + 0.24 * vignette - hatch * (isDark ? 0.06 : 0.05)));
        float ink = saturate(max(rib * 0.92, ros * 0.98));
        float tMix = saturate(0.5 + 0.5 * sin(sp.x * 3.1 - sp.y * 2.2));

        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (ink * 0.08 + hatch * 0.025);
            w1 = ink * (0.48 * (1.0 - tMix)) + hatch * 0.05 + leftGlow * 0.10;
            w2 = ink * (0.50 * tMix) + ros * 0.18;
        }
        else
        {
            float aInk = saturate(ink * 0.34 + hatch * 0.07);
            matte *= (1.0 - aInk * 0.78);
            w1 = aInk * (0.68 - 0.32 * tMix);
            w2 = aInk * (0.32 + 0.32 * tMix);
        }
        break;
    }

    // =========================================================================
    // 7: Leaf (macro botanical leaf midrib, arching lateral & capillary veins)
    // =========================================================================
    case 7u:
    {
        // Rotate canvas slightly so the botanical midrib sweeps diagonally
        float2 sp = float2((uv.x - 0.52) * aspect, uv.y - 0.52);
        float ang = -0.58 + (s0 - 0.5) * 0.14;
        float ca = cos(ang), sa = sin(ang);
        float2 lp = float2(sp.x * ca - sp.y * sa, sp.x * sa + sp.y * ca);

        // Gently curved central midrib
        float curve = 0.095 * sin(lp.x * 2.4 + s1 * 1.6);
        float dy = lp.y - curve;
        float absY = abs(dy);
        float side = (dy >= 0.0) ? 1.0 : -1.0;

        // Tapered central midrib ridge
        float midW = 0.011 * saturate(1.15 - lp.x * 0.45);
        float midrib = 1.0 - smoothstep(midW * 0.4, midW * 2.2, absY);
        float midShadow = exp(-absY * 22.0) * (0.45 + 0.55 * saturate(-dy * 18.0));

        // Arching primary lateral veins branching symmetrically (slightly staggered L/R)
        float vCoord = lp.x * 7.2 - pow(absY, 0.88) * 5.8 + side * 0.25;
        float vFrac = abs(frac(vCoord) - 0.5);
        float vThick = lerp(0.068, 0.022, saturate(absY * 1.4));
        float latVein = (1.0 - smoothstep(vThick * 0.35, vThick * 1.5, vFrac))
                      * smoothstep(0.005, 0.035, absY);
        // Gentle pillowed curvature of leaf lamina between primary veins
        float pillow = sin(saturate(vFrac * 2.0) * 1.57079);

        // Reticulated fine capillary vein mesh using 2-layer Voronoi
        float3 vor1 = voronoi_edge(lp * 18.5 + seedVec * 0.35, 0.88);
        float3 vor2 = voronoi_edge(lp * 36.0 + seedVec * 0.72, 0.85);
        float cap1 = 1.0 - smoothstep(0.015, 0.065, vor1.x);
        float cap2 = 1.0 - smoothstep(0.018, 0.075, vor2.x);
        float veins = saturate(max(midrib, max(latVein * 0.82, cap1 * 0.42 + cap2 * 0.22)));

        // Organic translucent chlorophyll backlight glow + gradual side fade (calm left, emerges right)
        float sideFade = smoothstep(0.16, 0.92, uv.x) * lerp(0.55, 1.0, smoothstep(0.06, 0.56, uv.y));
        float backlight = exp(-length(sp - float2(0.32 * aspect, 0.08)) * 1.75) * sideFade;
        float veinsF = veins * sideFade;
        float midF = midrib * sideFade;
        float latF = latVein * sideFade;
        float relief = lerp(1.0, 0.88 + 0.12 * pillow - midShadow * 0.10, sideFade);

        matte = lerp(bg, panel, saturate(0.16 + 0.20 * backlight + 0.10 * pillow * sideFade));
        matte *= isDark ? relief : lerp(0.97, 1.01, lerp(0.5, pillow, sideFade));

        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (midF * 0.038 + latF * 0.022 + backlight * 0.025);
            w1 = saturate(veinsF * 0.28 + backlight * 0.13 + leftGlow * 0.06);
            w2 = saturate(midF * 0.22 + latF * 0.16 + backlight * 0.14);
        }
        else
        {
            float aV = saturate(veinsF * 0.23 + (1.0 - pillow) * 0.04 * sideFade);
            matte *= (1.0 - aV * 0.78);
            w1 = aV * (0.72 - 0.25 * backlight);
            w2 = aV * (0.28 + 0.25 * backlight);
        }
        break;
    }

    // =========================================================================
    // 8: Shadow (architectural window-louver chiaroscuro & cast shadows)
    // =========================================================================
    case 8u:
    {
        float2 sp = float2(uv.x * aspect, uv.y);
        float tilt = 0.62 + (s0 - 0.5) * 0.08;
        float uS = sp.x * 0.54 + sp.y * tilt;
        float vS = sp.y * 0.82 - sp.x * 0.24;

        float distSrc = length(float2((uv.x - 1.05) * aspect, uv.y + 0.10));
        float penumbra = 0.055 + 0.16 * saturate(distSrc * 0.72);

        float slatPhase = frac(uS * 4.4 + s1 * 0.5);
        float slatLit = smoothstep(0.28 - penumbra, 0.28 + penumbra, slatPhase)
                      * (1.0 - smoothstep(0.76 - penumbra, 0.76 + penumbra, slatPhase));
        float mullion1 = smoothstep(0.02, 0.02 + penumbra * 0.6, abs(vS - 0.26));
        float mullion2 = smoothstep(0.02, 0.02 + penumbra * 0.6, abs(sp.x - 0.66 * aspect - sp.y * 0.35));
        float windowMask = smoothstep(1.55, 0.22, distSrc);
        float lit = saturate(slatLit * mullion1 * mullion2 * (0.25 + 0.75 * windowMask));

        float plaster = fbm4(sp * 14.0 + seedVec) * 0.08;

        matte = lerp(bg * (isDark ? 0.70 : 0.90), panel, saturate(0.18 + lit * 0.72 + plaster));
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (lit * windowMask * 0.10);
            w1 = saturate(lit * 0.32 + leftGlow * 0.08);
            w2 = saturate(lit * windowMask * 0.38);
        }
        else
        {
            float shadow = 1.0 - lit;
            float aS = saturate(shadow * 0.22);
            matte *= (1.0 - aS * 0.75);
            w1 = aS * 0.65;
            w2 = aS * 0.35;
        }
        break;
    }

    // =========================================================================
    // 9: Tattoo (Nordic ornamental knotwork & fine-line filigree margins)
    // =========================================================================
    case 9u:
    {
        float2 sp = float2(uv.x * aspect, uv.y);
        float2 rp = float2(uv.x - 0.78, uv.y - 0.50);
        rp.x *= aspect;

        float y = rp.y * 3.6 + s0 * 0.4;
        float waveA = rp.x - 0.11 * sin(y * 3.14159);
        float waveB = rp.x + 0.11 * sin(y * 3.14159);
        float braidA = 1.0 - smoothstep(0.008, 0.017, abs(waveA));
        float braidB = 1.0 - smoothstep(0.008, 0.017, abs(waveB));
        float outlineA = (1.0 - smoothstep(0.019, 0.025, abs(waveA))) * (1.0 - braidA);
        float outlineB = (1.0 - smoothstep(0.019, 0.025, abs(waveB))) * (1.0 - braidB);

        float overA = step(0.0, cos(y * 3.14159));
        float maskB = (overA > 0.5) ? smoothstep(0.014, 0.032, abs(waveA)) : 1.0;
        float maskA = (overA <= 0.5) ? smoothstep(0.014, 0.032, abs(waveB)) : 1.0;
        float knot = max(braidA * maskA, braidB * maskB);
        float knotLine = max(outlineA * maskA, outlineB * maskB);

        float2 mp = float2(abs(rp.x), frac(y * 0.5 + 0.5) - 0.5);
        float medR = length(mp * float2(2.6, 1.35));
        float medAng = atan2(mp.y, mp.x);
        float petal = 0.24 + 0.07 * cos(medAng * 8.0);
        float mandala = (1.0 - smoothstep(0.008, 0.022, abs(medR - petal)))
                      + (1.0 - smoothstep(0.006, 0.018, abs(medR - petal * 0.62))) * 0.75;
        float spineFade = smoothstep(0.46, 0.10, abs(rp.x)) * smoothstep(0.52, 0.36, abs(rp.y));

        float stippleHash = hash12(floor(float2(dtid.xy) * 0.5));
        float halo = exp(-min(abs(waveA), abs(waveB)) * 18.0) * spineFade;
        float dotwork = step(1.0 - halo * 0.62, stippleHash) * halo;

        float ink = saturate(max(knot * 0.85, max(knotLine, mandala * 0.85)) * spineFade + dotwork * 0.45);
        matte = lerp(bg, panel, saturate(0.18 + 0.18 * (1.0 - uv.y)));

        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (knotLine * spineFade * 0.14 + dotwork * 0.08);
            w1 = saturate(ink * 0.52 + leftGlow * 0.10);
            w2 = saturate(mandala * spineFade * 0.58 + knotLine * spineFade * 0.35);
        }
        else
        {
            float aT = saturate(ink * 0.38);
            matte *= (1.0 - aT * 0.84);
            w1 = aT * 0.68;
            w2 = aT * 0.32;
        }
        break;
    }

    // =========================================================================
    // 10: Nebula (cosmic fBM emission clouds, dust lanes & pinpoint starfield)
    // =========================================================================
    case 10u:
    {
        float2 sp = float2(uv.x * aspect, uv.y);
        float2 np = sp * 2.1 + seedVec * 0.4;
        float2 warp = float2(fbm4(np + float2(4.2, 1.7)), fbm4(np + float2(9.1, 6.3)));
        float cloud1 = fbm4(np + warp * 1.45);
        float cloud2 = fbm4(np * 1.65 - warp * 1.25 + float2(7.3, 12.1));
        float dust   = smoothstep(0.44, 0.72, fbm4(np * 1.35 + float2(19.4, 3.8)));

        // Gradual directional fade from right/lower-right into serene open left space
        float sideFade = smoothstep(0.14, 0.92, uv.x) * lerp(0.55, 1.0, smoothstep(0.04, 0.56, uv.y));
        float neb1 = pow(saturate(cloud1 * 1.24 - 0.28), 1.95) * (1.0 - dust * 0.62) * sideFade;
        float neb2 = pow(saturate(cloud2 * 1.22 - 0.32), 2.15) * (1.0 - dust * 0.48) * sideFade;
        float core = exp(-length(float2((uv.x - 0.78) * aspect, uv.y - 0.52)) * 1.85) * (0.5 + 0.5 * cloud1) * sideFade;

        float stars = 0.0;
        {
            float2 g1 = sp * 34.0 + float2(s0 * 9.0, s1 * 13.0);
            float2 i1 = floor(g1), f1 = frac(g1);
            float h1 = hash12(i1 * 2.31 + seedVec);
            if (h1 > 0.85)
            {
                float2 o = 0.20 + 0.60 * hash22(i1 + 11.3);
                float d = length(f1 - o);
                stars += exp(-d * 18.0) * (0.45 + 0.55 * frac(h1 * 13.7));
            }
            float2 g2 = sp * 12.0 + float2(s1 * 5.0, s0 * 11.0);
            float2 i2 = floor(g2), f2 = frac(g2);
            float h2 = hash12(i2 * 3.77 + 29.1 + seedVec);
            if (h2 > 0.89)
            {
                float2 o = 0.25 + 0.50 * hash22(i2 + 43.1);
                float2 q = f2 - o;
                float d = length(q);
                float spike = exp(-abs(q.x) * 42.0) * exp(-abs(q.y) * 7.5)
                            + exp(-abs(q.y) * 42.0) * exp(-abs(q.x) * 7.5);
                stars += (exp(-d * 15.0) * 0.82 + spike * 0.42) * (0.55 + 0.45 * frac(h2 * 9.1));
            }
        }
        stars = saturate(stars) * lerp(0.15, 1.0, sideFade);

        matte = lerp(bg * (isDark ? 0.88 : 0.98), panel, saturate(0.14 + core * 0.22 + neb1 * 0.14));
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (stars * 0.48 + core * 0.08);
            w1 = saturate(neb1 * 0.46 + core * 0.20 + stars * 0.14);
            w2 = saturate(neb2 * 0.48 + leftGlow * 0.08 + stars * 0.12);
        }
        else
        {
            float aN = saturate(neb1 * 0.18 + neb2 * 0.18 + core * 0.12 + stars * 0.14);
            matte *= (1.0 - aN * 0.78);
            w1 = aN * (neb1 + 0.35) / (neb1 + neb2 + 0.70);
            w2 = aN * (neb2 + 0.35) / (neb1 + neb2 + 0.70);
        }
        break;
    }

    // =========================================================================
    // 11: Mariusgenser (vertically flipped: calm lusekofte top, Marius yoke base)
    // =========================================================================
    case 11u:
    {
        float rows = 54.0;
        // Flipped vertically so gy=0..33 (bold Marius X-cross yoke) sits along the bottom
        // and gy=35..53 (calm sparse lusekofte lice-dot field) sits cleanly behind top text
        float2 g = float2(uv.x * aspect * rows * 0.92 + floor(s0 * 10.0), (1.0 - uv.y) * rows);
        int gx = int(floor(g.x));
        int gy = int(floor(g.y));
        float2 lf = frac(g);

        float vx = abs(lf.x - 0.5) * 2.0;
        float vy = frac((1.0 - lf.y) + vx * 0.42);
        float yarn = (0.78 + 0.22 * sin(vx * 3.14159)) * (0.86 + 0.14 * sin(vy * 3.14159));
        float fuzz = (hash12(float2(dtid.xy) * 0.5) - 0.5) * 0.03;

        int pat = 0;
        int mx8 = ((gx % 8) + 8) % 8;

        if (gy == 3 || gy == 4 || gy == 33)
        {
            pat = 1;
        }
        else if (gy >= 6 && gy <= 10)
        {
            int dy = gy - 6;
            int zig = (mx8 < 4) ? mx8 : (7 - mx8);
            if (dy == zig || dy == zig + 1) pat = 2;
            else if (dy == 2 && (mx8 == 0 || mx8 == 7)) pat = 1;
        }
        else if (gy == 12 || gy == 25)
        {
            pat = ((gx & 1) == 0) ? 2 : 1;
        }
        else if (gy >= 14 && gy <= 23)
        {
            int ry = gy - 14;
            int rx = ((gx % 10) + 10) % 10;
            int dx = abs(rx - 4);
            int dy = abs(ry - 4);
            bool onX = (abs(dx - dy) <= 1 && dx <= 3 && dy <= 3);
            bool centerDot = (dx == 0 && dy == 0);
            bool sideDiamond = (rx == 9 && (ry == 4 || ry == 5)) || (ry == 9 && (rx == 4 || rx == 5));
            if (centerDot) pat = 1;
            else if (onX || sideDiamond) pat = 2;
            else pat = 1;
        }
        else if (gy >= 27 && gy <= 31)
        {
            int dy = gy - 27;
            int zig = (mx8 < 4) ? (3 - mx8) : (mx8 - 4);
            if (dy == zig || dy == zig + 1) pat = 2;
        }
        else if (gy >= 35)
        {
            int lrow = gy - 35;
            if ((lrow % 3) == 0)
            {
                int shift = ((lrow / 3) & 1) * 2;
                if ((((gx + shift) % 4) + 4) % 4 == 0) pat = 2;
            }
        }

        float clothShade = yarn + fuzz;
        matte = bg * lerp(0.84, 1.04, clothShade);

        if (isDark)
        {
            if (pat == 1)
            {
                matte = lerp(bg, panel, 0.28) * clothShade;
                w1 = 0.36 * clothShade;
                w2 = 0.05 * clothShade;
            }
            else if (pat == 2)
            {
                matte = lerp(panel, float3(1.0, 1.0, 1.0), 0.20) * clothShade;
                w1 = 0.10 * clothShade;
                w2 = 0.30 * clothShade;
            }
            else
            {
                w1 = 0.04 * clothShade + leftGlow * 0.05;
                w2 = 0.02 * clothShade;
            }
        }
        else
        {
            if (pat == 1)
            {
                float a1 = 0.22 * clothShade;
                matte = lerp(bg, panel, 0.25) * (1.0 - a1 * 0.78);
                w1 = a1 * 0.85;
                w2 = a1 * 0.15;
            }
            else if (pat == 2)
            {
                float a2 = 0.16 * clothShade;
                matte = lerp(bg, panel, 0.55) * (1.0 - a2 * 0.72);
                w1 = a2 * 0.25;
                w2 = a2 * 0.75;
            }
            else
            {
                matte = lerp(bg, panel, 0.22 * clothShade);
                w1 = 0.03;
                w2 = 0.02;
            }
        }
        break;
    }

    // =========================================================================
    // 12: Matrix (subtle cascading digital rain glyphs along outer/right margins)
    // =========================================================================
    case 12u:
    {
        // Calm outer-margin focus: crisp cascade along right third & subtle left-bottom corner,
        // keeping the top header and center text calm and uncluttered
        float cols = 38.0;
        float rows = 34.0;
        float2 gp = float2(uv.x * aspect * cols, uv.y * rows);
        float2 ci = floor(gp);
        float2 cf = frac(gp);

        float colRnd = hash12(float2(ci.x, 7.3) + seedVec);
        float headRow = frac(colRnd * 3.7 + s0) * rows * 1.15;
        float trailDist = fmod(headRow - ci.y + rows * 2.0, rows);
        float trailLen = 7.0 + 11.0 * frac(colRnd * 11.3);
        float rain = smoothstep(trailLen, 0.0, trailDist) * step(0.28, colRnd);
        float isHead = exp(-trailDist * 2.2) * step(0.32, colRnd);

        // Minimalist procedural 3x5 dot-matrix katakana-inspired glyph strokes per cell
        float2 m = floor(cf * float2(4.0, 5.0));
        float inBox = step(0.16, cf.x) * step(cf.x, 0.84) * step(0.14, cf.y) * step(cf.y, 0.86);
        float gh = hash12(ci * 3.17 + m * 13.7 + seedVec);
        float stroke = step(0.46, gh) * inBox;
        // Soften individual pixel blocks cleanly
        float2 sf = frac(cf * float2(4.0, 5.0));
        float glyph = stroke * smoothstep(0.0, 0.18, sf.x) * smoothstep(1.0, 0.82, sf.x)
                             * smoothstep(0.0, 0.18, sf.y) * smoothstep(1.0, 0.82, sf.y);

        // Focus along right margin & bottom-right, softly fading toward upper-left
        float focus = saturate(smoothstep(0.44, 0.96, uv.x) * smoothstep(0.04, 0.26, uv.y)
                             + smoothstep(0.32, 0.0, uv.x) * smoothstep(0.55, 0.98, uv.y) * 0.42);
        float glow = rain * focus;

        matte = lerp(bg, panel, saturate(0.14 + 0.12 * (1.0 - uv.y)));
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (glyph * isHead * focus * 0.34);
            w1 = saturate(glyph * glow * 0.56 + glow * 0.10 + leftGlow * 0.06);
            w2 = saturate(glyph * isHead * focus * 0.58 + glow * 0.08);
        }
        else
        {
            float aM = saturate(glyph * glow * 0.32 + isHead * focus * 0.12);
            matte *= (1.0 - aM * 0.80);
            w1 = aM * 0.72;
            w2 = aM * 0.28;
        }
        break;
    }

    // =========================================================================
    // 13: Tron (receding perspective light-grid floor + faint horizon streaks)
    // =========================================================================
    case 13u:
    {
        float horizonY = 0.58; // lower 42% holds the perspective grid; top 58% stays serene
        float dy = uv.y - horizonY;
        float horizGlow = exp(-abs(dy) * 14.0) * (0.45 + 0.55 * smoothstep(0.15, 0.85, uv.x));
        float horizLine = exp(-abs(dy) * 160.0) * smoothstep(0.05, 0.30, uv.x);

        float grid = 0.0;
        float streak = 0.0;
        if (dy > 0.002)
        {
            float z = 0.36 / dy;
            float gx = (uv.x - 0.62) * aspect * z;
            float gz = z + s0 * 4.0;

            // Perspective-compensated line widths so distant lines fade cleanly without aliasing
            float distFade = exp(-z * 0.095) * smoothstep(0.002, 0.035, dy);
            float lx = 1.0 - smoothstep(0.015, 0.055 + z * 0.004, abs(frac(gx * 0.85 + 0.5) - 0.5));
            float lz = 1.0 - smoothstep(0.015, 0.065 + z * 0.005, abs(frac(gz * 0.75 + 0.5) - 0.5));
            grid = max(lx, lz) * distFade;

            // Subtle lone light-cycle glow trail gliding along one perspective lane
            float laneDist = abs(gx - (0.55 + (s1 - 0.5) * 0.9));
            streak = exp(-laneDist * 14.0) * exp(-abs(z - 4.2) * 0.45) * distFade;
        }

        // Subtle dark/light vanishing-point digital horizon glow in the lower-right sky
        float sunGlow = exp(-length(float2((uv.x - 0.72) * aspect, (uv.y - horizonY) * 1.8)) * 2.8)
                      * step(uv.y, horizonY + 0.02);
        float edgeFade = smoothstep(0.0, 0.16, uv.x) * smoothstep(1.0, 0.94, uv.x);

        matte = lerp(bg, panel, saturate(0.14 + horizGlow * 0.24 + sunGlow * 0.18));
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * ((grid * 0.10 + streak * 0.26 + horizLine * 0.18) * edgeFade);
            w1 = saturate((grid * 0.44 + horizGlow * 0.26 + horizLine * 0.35) * edgeFade + leftGlow * 0.06);
            w2 = saturate((streak * 0.68 + sunGlow * 0.30 + grid * 0.16) * edgeFade);
        }
        else
        {
            float aTr = saturate((grid * 0.26 + horizGlow * 0.14 + horizLine * 0.22 + streak * 0.22) * edgeFade);
            matte *= (1.0 - aTr * 0.78);
            w1 = aTr * 0.64;
            w2 = aTr * 0.36;
        }
        break;
    }

    // =========================================================================
    // 14: Event horizon (zoomed-in lower-right black hole covering ~1/3 frame)
    // =========================================================================
    case 14u:
    {
        // Anchored into the lower-right corner so the obsidian event horizon dome +
        // sweeping lensed photon ring & accretion glow spans roughly a third of the frame
        float2 ctr = float2((0.99 + (s0 - 0.5) * 0.04) * aspect, 0.96 + (s1 - 0.5) * 0.04);
        float2 sp = float2(uv.x * aspect, uv.y);
        float2 q = sp - ctr;
        // Relativistic disk inclination (-22 deg)
        float ta = -0.38;
        float ct = cos(ta), st = sin(ta);
        float2 rq = float2(q.x * ct - q.y * st, q.x * st + q.y * ct);

        float r = length(rq);
        float bhR = 0.52;

        // Razor-crisp glowing photon sphere rim hugging the giant dark event horizon dome
        float photonRing = exp(-abs(r - bhR * 1.02) * 32.0);
        float innerEdge  = exp(-abs(r - bhR * 0.995) * 72.0) * 0.65;
        // Soft gravitationally lensed upper Einstein corona wrapping around the limb
        float lensedHalo = exp(-pow((r - bhR * 1.14) * 5.2, 2.0)) * (0.48 + 0.52 * saturate(-rq.y * 2.0 + 0.45));
        float outerMist  = exp(-max(0.0, r - bhR) * 3.6) * 0.45;

        // Sweeping relativistic plasma accretion ribbon crossing the front of the singularity
        float diskY = rq.y + 0.09;
        float diskSpread = max(0.045, 0.17 - abs(rq.x) * 0.08);
        float diskBand = exp(-pow(diskY / diskSpread, 2.0) * 1.8)
                       * smoothstep(1.38, 0.45, abs(rq.x))
                       * smoothstep(bhR * 0.55, bhR * 0.95, r);
        float doppler = 0.58 + 0.42 * smoothstep(-0.65, 0.25, -rq.x);
        float filaments = 0.72 + 0.28 * fbm4(float2(r * 10.5, atan2(rq.y, rq.x) * 3.5) + seedVec * 0.5);
        float disk = diskBand * doppler * filaments;

        // Deep obsidian event-horizon shadow dome (blocks behind-disk corona, crossed by front sweep)
        float shadowMask = 1.0 - smoothstep(bhR * 0.96, bhR * 1.015, r);
        float frontDisk = disk * smoothstep(-0.06, 0.06, diskY + 0.05) * (0.35 + 0.65 * smoothstep(bhR * 0.62, bhR * 1.05, r));
        float backHalo  = (lensedHalo * 0.72 + outerMist + disk * 0.55) * (1.0 - shadowMask);
        float light     = saturate(photonRing * 0.72 + innerEdge * 0.45 + frontDisk * 0.70 + backHalo * 0.52);

        // Sparse distant stars subtly deflected around the gravity well in the open upper-left
        float2 lensedUv = sp + normalize(q + float2(1e-4, 1e-4)) * (0.042 / max(r, 0.30));
        float2 sg = lensedUv * 22.0 + seedVec;
        float sh = hash12(floor(sg) * 2.71);
        float star = (sh > 0.91) ? exp(-length(frac(sg) - 0.5) * 18.0) * (1.0 - shadowMask) * 0.48 : 0.0;

        matte = lerp(bg, panel, saturate(0.14 + backHalo * 0.18));
        if (isDark)
        {
            matte *= (1.0 - shadowMask * 0.92);
            matte += float3(1.0, 0.96, 0.90) * (photonRing * 0.16 + innerEdge * 0.14 + frontDisk * 0.12 + star * 0.46);
            w1 = saturate(backHalo * 0.44 + photonRing * 0.34 + leftGlow * 0.05);
            w2 = saturate(frontDisk * 0.46 + photonRing * 0.38 + lensedHalo * 0.24);
        }
        else
        {
            float aE = saturate(shadowMask * 0.24 + light * 0.24 + star * 0.12);
            matte *= (1.0 - aE * 0.78);
            w1 = aE * (0.68 - 0.28 * frontDisk);
            w2 = aE * (0.32 + 0.28 * frontDisk);
        }
        break;
    }

    // =========================================================================
    // 15: Spiderweb (ultra-delicate gossamer corner cobweb + tiny dewdrops)
    // =========================================================================
    case 15u:
    {
        // Anchored gracefully in the lower-right corner, fading out before the cards & top bar
        float2 hub = float2((0.92 + (s0 - 0.5) * 0.04) * aspect, 0.88 + (s1 - 0.5) * 0.04);
        float2 sp = float2(uv.x * aspect, uv.y);
        float2 q = sp - hub;
        float r = length(q);
        float ang = atan2(q.y, q.x);

        // 16 radial anchor spokes
        float spokes = 16.0;
        float sector = 6.2831853 / spokes;
        float sIdx = floor((ang + 3.1415926) / sector);
        float aOff = fmod(ang + 6.2831853, sector) - sector * 0.5;
        float spokeD = abs(aOff) * r;
        float silkW = invH * 1.25;
        float spokeLine = 1.0 - smoothstep(silkW * 0.4, silkW * 1.8, spokeD);

        // Concentric catenary-sagging silk rings between radial spokes
        float sag = 1.0 + 0.085 * cos((aOff / (sector * 0.5)) * 1.57079);
        float rScaled = pow(max(r * sag, 1e-4), 0.78) * 14.5;
        float ringIdx = floor(rScaled);
        float ringF = abs(frac(rScaled) - 0.5);
        float ringD = ringF / (14.5 * 0.78 * pow(max(r, 0.04), -0.22));
        float ringLine = (1.0 - smoothstep(silkW * 0.35, silkW * 1.75, ringD)) * smoothstep(0.03, 0.09, r);

        // Tiny glistening morning dewdrops clinging at select spoke-ring intersections
        float nodeH = hash12(float2(sIdx, ringIdx) + seedVec);
        float nodeD = length(float2(spokeD, ringD));
        float dew = (nodeH > 0.72) ? (1.0 - smoothstep(silkW * 1.4, silkW * 3.4, nodeD)) * smoothstep(0.08, 0.22, r) : 0.0;

        float webFade = smoothstep(0.98, 0.14, r);
        float silk = saturate(max(spokeLine, ringLine * 0.88)) * webFade;
        float dewLit = dew * webFade;

        matte = lerp(bg, panel, saturate(0.16 + 0.16 * (1.0 - uv.y)));
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * (silk * 0.14 + dewLit * 0.48);
            w1 = saturate(silk * 0.42 + dewLit * 0.35 + leftGlow * 0.06);
            w2 = saturate(dewLit * 0.65 + silk * 0.24);
        }
        else
        {
            float aS = saturate(silk * 0.30 + dewLit * 0.32);
            matte *= (1.0 - aS * 0.78);
            w1 = aS * 0.65;
            w2 = aS * 0.35;
        }
        break;
    }
    }

    // Sub-LSB triangular dither to eliminate 8-bit Mach banding across smooth gradients
    float d1 = hash12(float2(dtid.xy));
    float d2 = hash12(float2(dtid.xy) + float2(19.7, 47.3));
    matte += (d1 + d2 - 1.0) * (0.75 / 255.0);

    g_out[dtid.y * u_width + dtid.x] = uint2(pack_bgra8(matte), pack_weights_q8(w1, w2));
}
