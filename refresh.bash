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


