DIR1="/home/epiflight/Desktop/pywall/utils/recognizerAI/sessions_dataset/benignDataset/*.pcap"
DIR2="/home/epiflight/Desktop/pywall/utils/recognizerAI/sessions_dataset/benignDataset/*.pcapng"
for f in $DIR1 $DIR2
do
    # echo "Processing $f to $f.json"
    tshark -r $f -T json >$f.json
done