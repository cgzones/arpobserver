#pragma once

#define STRINGIFY(s) #s
#define STR(s)       STRINGIFY(s)

#define _wur_ __attribute__((warn_unused_result))
