/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "gtest/gtest.h"
#include "msquichelper.h"

extern "C" void QuicTraceRundown(void) { }

int main(int argc, char* argv[]) {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    ::testing::InitGoogleTest(&argc, argv);
    int res = RUN_ALL_TESTS();
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

}
