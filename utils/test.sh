initial=1

getTime1(){
	total_time=0
	for _ in {1..10}
	do
		start_time=$(date +%s.%N)
		echo "$@ > tmp1.txt"
 		end_time=$(date +%s.%N)
		timediff=`echo "$end_time - $start_time" | bc`
		total_time=`echo "$total_time + $timediff" | bc`
	done
	ans=`echo "$total_time*0.1" | bc`
	echo $ans
}

getTime2(){
	total_time=0
	for _ in {1..10}
	do
		start_time=$(date +%s.%N)
		$@ > tmp2.txt
 		end_time=$(date +%s.%N)
		timediff=`echo "$end_time - $start_time" | bc`
		total_time=`echo "$total_time + $timediff" | bc`
	done
	ans=`echo "$total_time*0.1" | bc`
	echo $ans
}


getTimeNull(){
	total_time=0
	for _ in {1..10}
	do
		start_time=$(date +%s.%N)
		$@ > /dev/null
 		end_time=$(date +%s.%N)
		timediff=`echo "$end_time - $start_time" | bc`
		total_time=`echo "$total_time + $timediff" | bc`
	done
	ans=`echo "$total_time*0.1" | bc`
	echo $ans
}

echo "numKeys,msgSize,signTime,verifyTime,signLength,blindSignTime,blindVerifyTime,blindSignLength"
for i in {1..25}
do
	filename="test_inputs/$initial.txt"
	echo "[$i] Processing: $filename"

	rm -f tmp1.txt tmp2.txt
	getTime1 "./urs -sign-text $filename -keypair pair.key -keyring pubkeyring.keys"
	t1=`getTime1 "./urs -sign-text $filename -keypair pair.key -keyring pubkeyring.keys"`
	t2=`getTime2 "./urs -sign-text $filename -keypair pair.key -keyring pubkeyring.keys -B"`
	t3=`getTimeNull "./urs -v $filename -k pubkeyring.keys -sig tmp1.txt"`
	t4=`getTimeNull "./urs -v $filename -k pubkeyring.keys -sig tmp2.txt -B"`

	l1=`wc -m tmp1.txt | cut -f1 -d' '`
	l2=`wc -m tmp2.txt | cut -f1 -d' '`
	echo "$initial,$t1,$t3,$l1,$t2,$t4,$l2"

	initial=$(($initial*2))
done