# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(mmap-in-swap) begin
(mmap-in-swap) open "words.txt"
(mmap-in-swap) file size of is 1819305 bytes
(mmap-in-swap) mmap "words.txt"
(mmap-in-swap) open "words.txt" for verification
(mmap-in-swap) verified contents of "words.txt"
(mmap-in-swap) close "words.txt"
(mmap-in-swap) end
EOF
pass;