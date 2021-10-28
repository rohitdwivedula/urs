go build -buildmode=c-shared -o urs.so
mv urs.h cpp/
mv urs.so cpp/
