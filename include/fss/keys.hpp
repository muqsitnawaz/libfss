
#pragma once

#include <vector>

namespace fss {
    struct DIFCW {
        u_char cs[16];
        u_char ct[2];
        uint64_t cv[2];
    };

    struct DPFCW {
        u_char cs[16];
        u_char ct[2];
    };

    struct DIFKey {
        u_char s[16];
        u_char t;
        std::vector<DIFCW> cw;
    };

    struct DPFKey {
        u_char s[16];
        uint64_t cw_last;
        std::vector<DPFCW> cw;
    };

    struct ReLUKey {
        ReLUKey() = default;

        DIFKey f[3], g[3];
        uint64_t r = 0; // r stores the random mask to blind the input
    };
}