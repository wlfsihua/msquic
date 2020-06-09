/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "gtest/gtest.h"
#include "msquichelper.h"

#include <vector>
#include <fstream>

extern std::vector<std::pair<uint64_t, uint64_t>> LoopbackTimingData;
extern std::vector<std::pair<uint64_t, uint64_t>> ConnectionTimingData;

extern "C" void QuicTraceRundown(void) { }

int main(int argc, char* argv[]) {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    ::testing::InitGoogleTest(&argc, argv);
    int res = RUN_ALL_TESTS();
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    {
        std::ofstream output{ "LoopbackResults.csv" };
        for (auto&& d : LoopbackTimingData) {
            output << d.first << ", " << d.second << std::endl;
        }
    }

    {
        std::ofstream output{ "ConnectionResults.csv" };
        for (auto&& d : ConnectionTimingData) {
            output << d.first << ", " << d.second << std::endl;
        }
    }

}
