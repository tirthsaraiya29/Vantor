#pragma once
#include "VantorBackend.h"
#include "mlinference.h"
#include <string>

void scan_full(
    SafeDB& safe_db,
    MLInference& ml,
    ScanHistoryDB& history_db,
    const std::string& scan_id
);
