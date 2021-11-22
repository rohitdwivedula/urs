go build -buildmode=c-shared -o urs.so
mv urs.h cpp/
mv urs.so cpp/
cd cpp
g++ hw.cpp ./urs.so -o hw.o