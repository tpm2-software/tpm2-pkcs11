# SPDX-License-Identifier: BSD-2-Clause

import sys

# Sunset python < 3 support
if sys.version_info[0] < 3:
    sys.exit("Python 3 or a more recent version is required.")