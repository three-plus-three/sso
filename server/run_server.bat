pushd %~dp0
rice embed-go
pushd %~dp0gssoserver
go build
cd ..
gssoserver\gssoserver.exe
popd
popd