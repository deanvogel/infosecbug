# TinyCC bug

## Bugged Compiler (this repo)
1. `./configure --cc=gcc` (ensure clean compilation)
2. `make clean`
3. `make`
4. `make install`

## In a clean compiler
1. `./configure --cc=tcc` (ensure bugged compilation)
2. `make clean`
3. `make`
4. `make install`

## Try out login.c
1. `tcc login.c`
2. `./a.out Mr.Dean`
3. `echo $?`
(Should return 0)
