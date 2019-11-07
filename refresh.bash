#!/bin/bash

KVER=4.7

# Refresh ath10k for 4.7 kernel
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k ./

# And for 4.4 kernel
KVER=4.4
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 4.9 kernel
KVER=4.9
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 4.13 kernel
KVER=4.13
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 4.16 kernel
KVER=4.16
mkdir -p ./ath10k-$KVER
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 4.19 kernel
KVER=4.19
mkdir -p ./ath10k-$KVER
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 4.20 kernel
KVER=4.20
mkdir -p ./ath10k-$KVER
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 5.2 kernel
KVER=5.2
mkdir -p ./ath10k-$KVER
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER

# And for 5.4 kernel
KVER=5.4
mkdir -p ./ath10k-$KVER
cp -ar ~/git/linux-$KVER.dev.y/drivers/net/wireless/ath/ath10k/* ./ath10k-$KVER



