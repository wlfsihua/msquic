/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "gtest/gtest.h"
#include "msquichelper.h"

#include "TestResults.h"

#include <vector>
#include <fstream>
#include <iostream>
#include <filesystem>

std::vector<std::shared_ptr<TestResult>> TestResults;

extern "C" void QuicTraceRundown(void) { }

int main(int argc, char* argv[]) {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    ::testing::InitGoogleTest(&argc, argv);
    int res = RUN_ALL_TESTS();
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    {
        std::ofstream output{ "Results.csv" };
        std::cout << "Writing " << TestResults.size() << " Items to file: " << std::filesystem::current_path() << std::endl;
        for (auto&& d : TestResults) {
            output << d->FolderName << ", " << d->GetTestResultForPrinting() << std::endl;
        }
    }
}
