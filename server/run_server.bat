pushd %~dp0gssoserver
go build 
cd ..
gssoserver\gssoserver.exe
popd