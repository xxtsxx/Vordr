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
//   0 : Cut planes     (layered shadowed diagonal folds + under-fold glow)
//   1 : Low-poly neon  (matte Delaunay relief + continuous neon zig-zag seams)
//   2 : Corner mosaic  (anti-aliased equilateral triangle corner dissolve)
//   3 : Optical arcs   (Apollonian circle-inversion refractive light caustics)
//   4 : Crystal rim    (anisotropic crystalline shards + dual-tone rim edges)
//   5 : Guardian sigil (emissive faceted Vordr sentinel crest + horizon bounce)
//   6 : Cipher rings   (golden-angle concentric cipher-wheel bead arcs)
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

    uint  u_mode;         // 0..6 procedural GPU style
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
    // 3: Optical arcs (Apollonian circle-inversion refractive caustics)
    // =========================================================================
    case 3u:
    {
        float2 z = (p - float2(0.06, 0.0)) * 2.05;
        float rotA = (s0 - 0.5) * 1.8;
        float ca = cos(rotA), sa = sin(rotA);
        z = float2(z.x * ca - z.y * sa, z.x * sa + z.y * ca);

        float caust1 = 0.0;
        float caust2 = 0.0;
        [loop]
        for (uint i = 0u; i < 5u; i++)
        {
            float fi = float(i);
            float2 c = float2(sin(fi * 2.05 + s0 * 5.0), cos(fi * 1.65 + s1 * 5.0)) * 0.52;
            float2 dz = z - c;
            z = abs(dz) / (dot(dz, dz) + 0.42) - 0.68;

            float dArc = abs(length(z) - (0.78 + 0.05 * s1));
            float w = (0.58 - fi * 0.09);
            float core = exp(-dArc * 32.0) * w;
            float halo = exp(-dArc * 6.0) * w * 0.30;
            if ((i & 1u) == 0u)
                caust1 += core + halo;
            else
                caust2 += core + halo;
        }

        matte = lerp(bg, panel, saturate(0.22 * spot + 0.10 * (1.0 - uv.y)));
        if (isDark)
        {
            matte += float3(1.0, 1.0, 1.0) * pow(saturate((caust1 + caust2) * 0.48), 2.6) * 0.26;
            w1 = caust1 * 0.46;
            w2 = caust2 * 0.40;
        }
        else
        {
            float a1 = saturate(caust1 * 0.32);
            float a2 = saturate(caust2 * 0.28);
            matte *= (1.0 - a1) * (1.0 - a2);
            w1 = a1 * (1.0 - a2);
            w2 = a2;
        }
        break;
    }

    // =========================================================================
    // 4: Crystal rim (anisotropic crystalline shards + rim highlights)
    // =========================================================================
    case 4u:
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
    // 5: Guardian sigil (emissive low-poly Vordr sentinel crest + horizon)
    // =========================================================================
    case 5u:
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
    // 6: Cipher rings (golden-angle concentric cipher-wheel bead arcs)
    // =========================================================================
    case 6u:
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
    }

    // Sub-LSB triangular dither to eliminate 8-bit Mach banding across smooth gradients
    float d1 = hash12(float2(dtid.xy));
    float d2 = hash12(float2(dtid.xy) + float2(19.7, 47.3));
    matte += (d1 + d2 - 1.0) * (0.75 / 255.0);

    g_out[dtid.y * u_width + dtid.x] = uint2(pack_bgra8(matte), pack_weights_q8(w1, w2));
}
