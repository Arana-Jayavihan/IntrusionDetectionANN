if [ $# == 1 ]; then
    sudo tshark -T json -i wlo1 -c $1 -Y "not (ip.src == 192.168.1.28)" > tmpData/benign.json 
    python dumpBenign.py
    python fetchSuspiciousData.py
    python shuffle.py
else
    echo "Enter benign data capture packet limit"
fi
