# welcome to snifty sniff
# Do the following to see this in action:

cd snifty
go install ss/ss.go
./genTraffic.sh &
ss -f config/config.json 
