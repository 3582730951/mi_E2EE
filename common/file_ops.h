#pragma once

#include <stdint.h>

#include "mi_common.h"

MI_Result SecureEraseFile(const char* path, uint64_t size_hint);
