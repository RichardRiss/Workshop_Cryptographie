#!/usr/bin/env python3

# The message given below is an English text in ASCII encoding without
# line breaks. It was encrypted in AES-CTR with a 256 bit key.  Due to an
# error in the implementation of CTR mode, the counter's cycle length is
# only 10 (hex 0x0A). Decrypt the message!
#
# The program should show how you solved the problem, i.e. the
# step you took in order to decode the message should be
# identifiable.
#
# Note that your program shall only decode this specific text. I will
# not run it with any other ciphertext.

import hashlib


# from typing import list


def hex2str(s: str) -> str:
    return "".join(map(lambda x: chr(int(x, 16)), s.split()))


ciphertext: str = hex2str("""
70 6A AC 10 0B 67 44 43 B7 62 2F 69 03 16 79 09
B7 1E 81 AE 65 23 B1 CB E0 2B 4E DE 51 5B A3 58
D9 D5 E3 36 9F 57 A4 08 E0 D0 05 4C 62 06 B4 47
11 13 AF E7 86 DE 73 CA DD 02 EB 4C 77 15 36 CC
A7 E4 1A C9 65 10 74 81 BA E1 44 02 81 04 9A EA
88 2C E0 26 10 A6 AF A3 99 13 29 91 5E 77 4B 2B
71 AC 48 A0 B0 8A A0 48 5F E5 C1 50 E4 AD 7C C8
48 A6 28 5E F7 10 22 DB 72 6E CA 8E 29 57 D6 EA
5A 73 1E 4D 4F D8 57 2F 61 81 31 F7 AA 09 15 FA
A2 CB C0 8F 54 13 53 49 C3 2A 01 18 6A 57 3E 05
4B 69 EA 1C 11 22 18 0C B1 7E 2F 58 07 1E 6E 0D
F6 18 80 AE 67 34 AB C7 FC 2A 1D 80 14 49 AB 43
C4 C4 EB 6F C7 1F B5 47 B6 CB 07 57 62 06 FA 08
1F 5A B1 AE 9C D2 32 D3 DE 18 A8 50 38 5D 3B 85
B1 AA 02 C3 7D 11 75 D3 BE A9 40 02 C5 4C 9C B8
83 3D EE 24 0D A6 B2 A2 99 23 36 9D 4D 7D 54 2F
3F BC 0C E5 B4 87 EF 76 5F A8 CF 49 E6 AC 35 8B
68 E7 2F 5F F7 0B 6E D7 33 73 89 DA 7E 50 CD F5
5A 68 15 4D 53 88 46 23 35 96 30 A7 BB 09 0A FA
BE D6 94 9E 11 5E 01 45 DC 7F 1C 02 66 40 3E 14
19 7F E9 1E 1D 29 50 0C BD 74 66 5B 06 18 63 45
B9 16 C5 E6 6A 22 F8 D9 E1 3D 05 97 14 5C A7 52
D8 DE E3 7A 92 13 E1 5C F9 99 03 53 78 18 FB 4F
1E 49 A7 AE 8E D5 21 9D D6 0E FA 50 36 14 3D CC
A7 F8 02 C9 6E 06 30 C0 A3 ED 01 01 C8 1F 8F B8
83 27 F3 34 5E AE BD A3 CB 50 31 94 47 7B 50 62
71 B0 4F B2 A6 99 E5 77 16 A8 C6 5C B6 B7 23 C8
6F E9 2F 16 FD 0B 3A D6 20 65 C9 83 29 4B DC EE
0A 72 15 5B 42 9A 4F 25 68 C8 74 E6 B6 08 4A BF
B8 D7 89 95 59 12 0A 0C 8D 7E 1A 50 66 5C 6E 19
58 65 E2 5D 1D 29 51 0C B7 62 2F 5B 18 18 2D 08
BF 03 86 E1 6D 32 BD DE FA 26 01 C2 47 01 E2 73
C2 C4 A7 7E 8E 1F A8 5B B6 D7 0D 57 37 00 FC 4D
57 60 B3 FB 89 C8 36 9D DD 0E A8 4B 39 1E 36 CC
B5 EB 03 88 3C 2C 75 C0 BF FA 01 03 C7 4C 96 A7
9A 3B EE 34 11 E8 B6 A9 D7 04 6A DC 4F 76 5C 6E
25 B0 45 E5 B0 9B E9 69 56 A8 C6 5C F7 A8 39 8D
73 A6 39 43 EA 01 2B D1 72 6F C3 DA 6E 5C D7 F8
08 7C 17 08 42 96 40 32 24 97 21 EB B1 18 1F BF
AD D1 84 C7 50 11 10 4B C8 78 0C 5C 23 4C 7F 03
5C 2C EF 12 1F 25 5D 42 BD 74 2F 58 06 03 65 45
A2 18 80 AE 6D 30 AC DB FC 2E 02 8C 50 4A A1 50
CE 90 E8 70 CB 50 AD 4C B6 D8 05 46 37 00 FB 08
12 41 A3 FD 8D 9A 35 CF DA 06 A8 4C 3E 0E 73 81
AB E4 14 86 71 14 7E D8 ED E6 47 4C D5 04 9A EA
9E 21 E8 32 19 EE AF BF 99 11 28 98 0E 76 57 3A
38 B7 4E B6 EF CF E1 6B 5E A8 C3 4C F5 B6 70 89
6D F5 34 16 F7 03 6E CB 3A 65 85 8E 6C 4B D4 F4
14 72 17 47 4C 81 0F 60 36 9B 3D E4 B0 4C 0E FA
EC DE 83 96 48 17 01 45 C9 2A 11 05 71 4D 70 12
19 64 E5 0E 52 34 5C 43 AA 64 2F 5C 1B 16 74 45
BF 1E C5 DD 73 30 BB CB E2 2E 00 C8 1A 0F 8A 54
97 D8 E6 65 C7 1F B5 40 F3 CB 07 45 78 06 F1 04
57 41 A7 FF 9D DF 20 C9 D0 0F A8 49 32 5D 27 83
E2 F8 15 D6 70 0C 30 C8 A3 A9 49 05 D2 4C 9D AF
82 28 EB 21 5E F2 B4 EC CD 07 29 DC 5D 68 5D 2D
38 B9 4C E5 AC 8D EA 60 59 FC C7 56 F8 AD 7C C8
6E E8 3E 16 F7 03 6E DE 3C 20 CC 94 7D 5C D5 F1
1F 7E 0F 5D 4A 94 0F 60 35 9B 31 A7 B7 18 0E FA
BE 9F 8F 81 1D 1F 53 4D C2 78 14 1C 23 4A 7F 01
4C 7E E9 53 52 13 5C 49 F8 76 66 5D 1C 03 2D 0A
B4 1A 80 ED 77 38 B7 C0 AE 26 1D 80 14 5B AA 50
C3 90 E6 36 AD 53 A0 5C FA D8 0C 47 72 06 B8 08
04 56 A7 E7 86 DD 73 DC 95 27 E1 4A 32 51 73 9F
A7 EF 03 86 6F 1A 7D C4 B9 E1 48 02 C6 4C 8B A2
8B 3D A7 2A 0B F5 AF EC DB 15 66 A8 66 51 7B 05
71 AC 4F E5 B7 87 E5 25 5F F1 CB 19 F7 AD 70 9F
64 EA 37 16 F9 16 6E F3 1D 4E E2 DA 7D 56 99 E9
12 78 5B 4D 52 9D 03 68 2E 87 3C E2 AA 1B 0F EC
A9 9F 89 93 1D 09 1C 55 C1 6E 55 1E 6C 50 3E 17
5C 2C FA 14 01 2E 56 40 BD 3C 2F 46 09 57 64 11
F6 18 84 EA 23 3F B7 DA AE 3C 01 C1 51 0F B6 59
DE D3 EC 78 8E 4C B2 01 AD 99 03 4D 73 54 F7 47
19 40 A7 FF 9D DF 3D C9 D9 12 A8 4C 32 5D 3C 99
A5 E2 04 86 34 1C 64 81 A4 FA 01 0D D3 0B 8A AF
8E 60 A7 33 11 A6 BA AF D2 1E 29 8B 42 7D 5C 29
34 F8 54 AD A2 9B A0 6D 53 FB 8E 5A F9 AB 3E 9C
73 FF 36 53 F6 45 2F CD 37 20 CB 95 7D 19 D6 F3
16 64 5B 44 44 96 44 60 20 9D 30 A7 BA 1E 09 FE
A8 93 C0 85 48 0A 53 41 C1 79 1A 50 2B 50 76 1A
4C 6B E4 5D 16 28 41 4E AC 7C 6A 5C 1C 57 64 0B
F6 11 C5 F8 66 23 A1 8E FD 23 07 CB 5C 5B E2 55
D2 D7 F5 73 8E 16 E1 7C DE F0 21 68 37 1B E6 08
3F 7A 85 C6 C6 9A 07 D5 DC 18 A8 4B 35 17 36 8F
B6 E3 1F C8 3C 1C 63 81 BD E5 40 19 D2 05 9D A6
8F 65 A7 26 10 E2 F7 EC CD 1F 66 AF 5E 79 5B 2B
3D B9 4E A1 A6 9D F3 29 1A E9 C2 54 F9 AD 24 C8
68 F4 29 53 EB 0C 3D CB 3B 62 C9 9F 25 19 CA F2
5A 69 13 49 5F D4 03 09 61 90 3B E9 BE 09 15 EC
E0 9F 97 8F 58 10 53 69 8D 6C 1C 02 70 50 3E 1D
5C 6D FE 19 52 2E 40 00 F8 59 2F 44 01 12 7A 45
B8 1F 91 AE 74 39 B9 DA AE 3B 01 8C 46 4A B2 5D
CE 9E A7 54 9E 4B E1 45 EF 99 12 4C 78 06 B4 47
1B 57 E2 E8 9A D3 36 D3 D1 4C FB 04 36 13 20 9B
A7 F8 50 C7 6C 05 75 C0 BF FA 01 18 CE 4C 92 AF
CA 2A E8 2A 0E EA BE B8 DC 1C 3F DC 5A 77 18 23
34 BD 54 E5 AA 9B AE 25 18 C1 8E 58 F2 B3 39 9C
2D A4 7B 45 F9 0C 2A 9F 3A 65 88 8D 61 5C D7 BD
33 3D 16 4D 45 8C 4A 2F 2F 96 30 A7 AC 03 46 F7
A5 D2 C0 93 55 17 00 00 C2 68 1F 15 60 50 77 1A
57 21 AE 34 52 26 50 41 B1 64 2F 5B 07 12 2D 11
A4 05 91 E6 23 3E BE 8E F7 20 1B DE 14 4C B0 58
C3 D9 E4 31 98 1F A7 49 F5 CD 11 0F 37 16 E1 5C
57 7A E2 EA 8D D4 2A 9D DD 02 FB 04 34 12 3D 8F
AE FF 03 CF 73 1B 63 8F ED C0 55 4C C8 1F DF BE
98 3C E2 67 0A EE BA B8 99 07 23 DC 46 79 4E 2B
71 AA 45 A4 AF 83 F9 25 53 E6 8E 7F FA BF 24 84
60 E8 3F 16 F9 45 1A D7 3B 72 C1 DA 7C 57 CB F8
19 72 1C 46 42 82 46 24 61 B7 3D EA BD 02 15 F6
A3 D1 C0 84 5C 12 1F 45 C9 2A 52 18 66 4D 79 1D
4D 2B A0 5D 18 32 47 58 F8 71 7C 0F 06 03 2D 0C
A5 50 84 E2 70 3E F8 DA FC 3A 0B 8C 40 47 A3 45
97 C9 E8 63 CB 57 A0 5E F3 99 10 46 76 18 F8 51
57 5A AC AE BB CA 32 DE D0 07 E9 4A 33 5D 32 CC
84 E5 05 D4 68 1D 30 D4 A3 FB 44 0F CE 0B 91 A3
90 2C E3 67 3A EF B6 A9 D7 03 2F 93 40 34 18 2D
30 B4 4C A0 A7 CF E2 7C 1A E6 C1 19 F8 BF 3D 8D
21 E7 2F 16 E8 17 2B CC 37 6E D1 D6 29 5B CC E9
5A 6A 13 41 48 90 03 09 61 84 3D EB B4 4C 05 FE
A0 D3 C0 C0 58 06 07 52 CC 27 1D 15 6A 43 76 01
1E 22 AC 3F 07 33 14 5B BD 30 6C 4E 01 57 63 0A
F6 1D 8A FC 66 71 AC CF E5 2A 4E CF 5B 48 AC 58
CD D1 E9 75 8E 1F AE 4E B6 D6 17 51 37 53 FC 4D
1E 54 AA FA CF 9A 27 D5 D4 05 A8 5D 38 08 73 8F
A3 E4 50 C9 7A 55 69 CE B8 FB 01 4B C4 14 8B B8
8B 64 EF 22 17 E1 B3 B8 9E 5E 66 B9 58 7D 56 6E
18 F5 57 AD AC CF E8 64 4C ED 8E 5B F3 BB 3E C8
68 E8 7B 65 E8 04 2D DA 3E 61 CB 9E 25 19 D8 F3
1E 3D 13 49 5D 9D 03 28 20 97 74 F3 B0 09 46 EF
BE D6 96 8E 51 1B 14 45 8D 65 13 50 76 4A 7A 10
4B 7F F8 1C 1C 23 5D 42 BF 30 69 40 1D 57 79 12
B3 1E 91 F7 2E 37 B7 DB FC 6F 06 C3 41 5D B1 11
C3 D8 E2 36 86 5A A0 46 FF D7 05 03 78 12 B4 0F
1F 56 AB E9 80 CE 74 90 D0 1D ED 4A 77 34 73 8F
A3 E4 1E C9 68 55 7E CE BA A9 42 03 CC 1C 8D AF
82 2C E9 23 5E EF AF E0 99 1E 29 8E 0E 6A 5D 2F
3D B1 5A A0 E3 86 F4 25 58 F1 8E 4D FE BB 70 9B
64 E8 28 53 B8 0A 28 9F 21 69 C2 92 7D 19 D6 EF
5A 7F 02 08 4A 96 5A 60 31 81 3B E4 BD 1F 15 BF
A3 D9 C0 95 58 1F 00 4F C3 31 55 39 23 47 7F 1B
19 6E F9 09 52 26 44 5C AA 75 67 4A 01 13 2D 0C
A2 50 87 F7 23 37 B9 C7 FA 27 40 8C 16 7B AA 54
97 C2 E2 77 98 50 AF 08 FF CA 42 4C 75 02 FD 47
02 40 EC AE AC D3 3E D8 DB 18 E1 4B 39 5D 3A 81
B2 E6 19 C3 6F 55 74 C8 BF EC 42 18 C8 03 91 E6
CA 20 EA 37 12 EF BE BF 99 1D 23 9D 5D 6D 4A 2B
3C BD 4E B1 EF CF E9 68 4A E4 C7 5C E5 FE 24 80
64 A6 36 59 EA 00 6E DE 3C 64 85 8E 61 5C 99 F1
1F 6E 08 06 0B B6 4C 37 6D D3 35 EB B4 4C 09 EA
BE 9F 8C 8E 53 1B 00 00 CC 78 10 50 46 75 4B 34
75 40 D5 5D 13 29 50 0C 91 5E 49 66 21 3E 59 20
85 39 A8 CF 4F 1D 81 8E FA 27 07 CF 5F 0F EA 5E
C5 90 EF 7F 8C 57 ED 08 E1 D1 0B 40 7F 11 E2 4D
05 13 BB E1 9D 9A 3F D4 DE 0E A1 1F 77 1E 3C 82
B1 EF 01 D3 79 1B 64 CD B4 A5 01 18 C9 09 8D AF
CA 20 F4 67 10 E9 AF A4 D0 1E 21 DC 47 76 18 3A
39 BD 4D E5 B7 80 A0 69 5F E9 CA 19 F9 AB 22 C8
6C EF 35 52 EB 45 3A D0 72 74 CD 9F 29 5A D6 F3
19 78 0B 5C 42 97 4D 60 2E 95 74 F3 B0 0D 12 BF
88 D6 8D 82 53 0D 1A 4F C3 24 55 3E 6C 04 39 11
5C 60 E5 1E 13 33 51 0C B5 79 6C 5D 00 1A 68 11
B3 02 C2 A3 62 22 F8 C6 EF 3C 4E CE 51 4A AC 11
C4 C5 E0 71 8E 4C B5 4D F2 99 00 5A 37 1B FA 4D
57 47 AD E1 C8 D2 32 CE C1 12 A8 77 27 1C 30 89
AE EB 1E C2 3C 16 62 C8 B9 E0 42 41 D6 03 8A A6
8E 69 EE 29 5E F2 B3 A9 99 1C 23 9D 5D 6C 18 2F
27 B9 49 A9 E3 9A F3 3E 1A EE C1 4B B6 A9 35 C8
72 EE 34 43 F4 01 6E D1 3D 74 85 91 67 56 CE BD
2D 55 3A 7C 0B AC 6C 60 0C B6 15 D4 8D 3E 23 B3
EC F1 AF B5 1D 37 3D 00 FA 42 34 24 23 60 57 27
7C 4F D8 34 3D 09 1A 0C 8F 78 6A 41 4F 00 68 45
A5 15 80 AE 62 71 94 C7 E0 2A 42 8C 43 4A E2 42
D2 D5 A7 65 84 52 A4 5C FE D0 0C 44 37 00 FC 49
03 13 AB FD C8 D6 3C D3 D2 4B E9 4A 33 5D 11 BE
8B CD 38 F2 27 55 52 F3 84 CE 69 38 EF 29 AC 99
C6 69 E6 34 5E F1 BE A0 D5 50 27 8F 0E 74 5D 20
36 AC 48 E9 E3 86 F3 25 54 ED CD 5C E5 AD 31 9A
78 A6 2F 59 B8 11 26 DA 72 65 DD 93 7A 4D DC F3
19 78 5B 47 4D D8 42 60 0D 9A 3A E2 E3 4C 0F F9
EC CB 88 82 1D 1C 01 49 CA 62 01 1E 66 57 6D 55
4F 6D E2 14 01 2F 51 5F F4 30 7B 47 0A 57 41 0C
B8 15 C5 E7 70 71 BD D6 FA 26 00 CB 41 46 B1 59
D2 D4 A9 36 A3 5A AF 4B F3 95 42 42 7B 18 B4 45
0E 13 84 E2 89 CE 3F DC DB 0F A8 42 25 14 36 82
A6 F9 5D D1 74 10 7E 81 84 A9 55 0D CD 07 DF BE
85 69 F3 2F 1B EB FB AD DB 1F 33 88 0E 6C 50 2B
71 AD 4E B7 A6 8C EF 62 54 E1 D4 5C F2 FE 14 81
6C E3 35 45 F1 0A 20 9F 25 68 CC 99 61 19 D0 EE
5A 6E 14 45 4E 90 4C 37 61 85 3D F4 B1 0E 0A FA
EC D6 8E C7 5C 5E 3F 49 C3 6F 58 03 62 5D 32 55
1E 4D E4 51 52 3E 5B 59 F8 7D 6A 4E 01 57 4F 37
9F 37 AD DA 4D 14 8B FD A9 75 4E CD 5A 4B E2 46
DF D5 E9 36 A2 1F B3 4D E6 D5 1B 0F 37 53 DA 47
5B 13 8B AE 85 DF 32 D3 95 0A A8 56 32 1C 3F CC
86 E3 1D C3 72 06 79 CE A3 AE 0D 4C D5 04 9A B3
CA 28 F3 67 11 E8 B8 A9 99 02 23 88 41 6A 4C 62
71 FF 74 AD A6 81 A0 68 5F E9 DD 4C E4 BB 70 81
75 AA 7B 59 EA 45 3A DA 3E 6C 85 8F 7A 19 D0 F3
5A 6A 13 49 5F D8 47 29 33 96 37 F3 B1 03 08 BF
A5 CB C0 82 45 0A 16 4E C9 79 52 4B 23 45 70 11
19 78 E4 14 01 67 47 45 B4 75 61 4C 0A 04 2D 08
B3 5C C5 E8 6C 23 F8 E7 AE 2C 0F C2 14 4B AD 11
D9 D5 EE 62 83 5A B3 06 B6 F6 0C 4F 6E 54 ED 4D
04 47 A7 FC 8C DB 2A 91 95 1C E0 41 39 5D 27 84
A7 AA 33 CE 75 10 76 81 8E E0 53 0F CD 09 DF E2
83 27 A7 28 0A EE BE BE 99 07 29 8E 4A 6B 18 21
24 AA 00 8D AA 88 E8 25 6A FA C7 5C E5 AA 79 C8
62 E7 36 53 B8 11 21 9F 3B 6E D6 8A 6C 5A CD BD
0E 75 1E 08 78 8C 42 34 24 D3 04 F5 B1 1F 09 F1
EC DE 8E 83 1D 0E 12 49 C9 2A 18 15 23 4C 77 06
19 7F E9 0B 17 29 40 44 F8 71 61 41 1A 16 61 45
A0 19 96 E7 77 7D F8 CF E0 2B 4E DB 5C 4A AC 11
D1 DF F5 36 9F 57 A4 08 E5 DC 14 46 79 00 FC 08
03 5A AF EB C8 D2 36 9D C5 1E FC 04 3A 18 73 98
AA EF 50 D7 69 10 63 D5 A4 E6 4F 40 81 4B A8 AB
99 69 CE 67 1F E8 A2 EC DB 15 32 88 4B 6A 07 69
71 91 00 B1 B1 86 E5 61 1A FC C1 19 E6 AC 3F 9E
64 A6 2F 59 B8 0D 27 D2 72 74 CD 9B 7D 19 D1 F8
5A 6A 1A 5B 0B DF 4B 29 26 9B 73 AB F8 0D 15 BF
BB DA 8C 8B 1D 1F 00 00 C1 65 1B 17 23 45 70 11
19 6E FE 12 13 23 18 0C B9 7C 7B 47 00 02 6A 0D
F6 18 80 AE 67 38 BC 8E E0 20 1A 8C 5F 41 AD 46
97 D9 F3 38 CB 7D B4 5C B6 CE 0A 42 63 54 E3 49
04 13 AA E7 9B 9A 21 D8 C5 07 F1 1B 77 5A 0A 83
B7 AA 03 C7 65 55 59 81 AC E4 01 4E C9 05 98 A2
C8 72 A7 2A 1B E7 A8 B9 CB 15 66 91 57 38 1A 26
38 BF 48 E8 AD 8A F3 76 18 A8 CF 57 F2 FE 19 C8
76 EF 37 5A B8 07 2B D3 3B 65 D3 9F 29 40 D6 E8
54 3A 5B 7F 43 99 57 60 22 9C 21 EB BC 4C 2F BF
A8 D0 DF C7 75 11 04 00 CE 65 00 1C 67 04 57 55
54 69 E9 09 52 2F 5D 5F F8 73 67 4E 03 1B 68 0B
B1 15 DA AE 4A 71 AF CF FD 6F 0D DE 41 5C AA 54
D3 8B A7 77 85 5B E1 40 F3 99 0E 46 71 00 B4 5C
1F 56 E2 FC 87 D5 3E 9D C1 19 E1 51 3A 0D 3B 8D
AC FE 5E
""")

'''
What do we know?
    block length 256Bit?
    256 bit key -> 15 Round Keys
    counter somewhere between 0 and 9
    Text is english alphabet without linebreak -> A-z + space
    ACII 097-122 (a-z) + 065-090 (A-Z) + 032 (Space) all dezimal
    Average word length in english alphabet is 6 -> high probability to have a space on one line
    
    -->
    decode all bytes that use the same keybyte with ascii A-z + Space
    record most is_ascii() occurences
    keybyte with most matches wins
    -->
'''

# ascii value for evaluation
high_prio_ascii = [ord(i) for i in ['e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u']]
ascii_text_chars = list(range(97, 122)) + [32] + list(range(65, 90))  # + [40, 41, 44, 46, 59]

# xor predicted key with extracted letter
def bxor(a, b):
    return bytes([ord(x) ^ y for (x, y) in zip(a, b)])


def guess_single_byte_xor(cipherlist):
    ##################
    # loop over all possible keys for 1 Byte
    # extend the key to match length of cipherlist
    # decrypt each byte and assign a score for english language
    # additional score for recurrent letters
    # key with highest score wins
    # return decrypted letters, key and score
    ##################
    best = None
    for i in range(2 ** 8):
        candidate_key = i.to_bytes(1, byteorder='big')
        keystream = candidate_key * len(cipherlist)
        candidate_message = bxor(cipherlist, keystream)
        # get all possible combinations
        sum_letters = sum([x in ascii_text_chars for x in candidate_message])
        sum_letters += sum([x in high_prio_ascii for x in candidate_message])
        # if the obtained message has more letters than any other candidate before
        if best == None or sum_letters > best['sum_letters']:
            # store the current key and message as our best candidate so far
            best = {"message": candidate_message, 'sum_letters': sum_letters, 'key': candidate_key}
    return best


def fixed_nonce_attack(ciphertext):
    ##################
    # Cut Ciphertext into chunks of 128Bit * 10 because that's the generated key length
    # extract last cipherblock because it is not 128Bit and has to be reassembled diffrently
    # for every byte in the key, put the corresponding letter from each block into a list
    # guess the key for each letter-list
    # reassemble the decrypted letters and use the corresponding keys to decrypt the incomplete last block
    # return as plaintext
    ##################
    chunk_size = 10 * 16
    list_cipher = []
    for i in range(0, len(ciphertext), chunk_size):
        list_cipher.append(ciphertext[i:i + chunk_size])
    # Drop shorter block
    spare_cipher = list_cipher[-1]
    list_cipher = list_cipher[:-1]
    columns = [guess_single_byte_xor(b) for b in zip(*list_cipher)]
    spare_plaintext = ''.join([bytes(bxor(i, columns[c]['key'])).decode('ascii') for c, i in enumerate(spare_cipher)])
    messages = [col['message'] for col in columns]
    return ''.join([bytes(msg).decode('ascii') for msg in zip(*messages)]) + spare_plaintext


def decode(ciphertext: str) -> str:
    """Return plaintext as string."""
    ##################
    # YOUR CODE HERE #
    ##################
    return (fixed_nonce_attack(ciphertext))


if __name__ == '__main__':
    # plaintext = fixed_nonce_attack(ciphertext)
    # print(hashlib.sha256(plaintext.encode('ascii')).hexdigest())
    # bruteforce_key("70 6A AC 10 0B 67 44 43 B7 62 2F 69 03 16 79 09")
    plaintext: str = decode(ciphertext)
    assert (hashlib.sha256(plaintext.encode('ascii')).hexdigest() ==
            '0cc9a5db2868b285f35c8217bd8e33dcec88a2cb8346223eeabc565060904883')
