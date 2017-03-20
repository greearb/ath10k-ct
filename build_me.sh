#!/bin/bash

# Make a copy...
rm -r tmp/ath10k.build
mkdir -p tmp
KVDIR_EXTRA=

# Create a build script
if [[ "_$KBL" == "_" ]]
then
    echo "Enter your kernel's build directory:"
    read KBL
fi

if [[ "_$CTAVER" == "_" ]]
    then
    echo "Enter kernel version to build for: 4.4  (or enter for default which is 4.7 currently):"
    read CTAVER
fi

if [[ "_$CTAVER" == "_4.4" ]]
    then
    KVDIR_EXTRA="-4.4"
fi

cp -ar ath10k${KVDIR_EXTRA} tmp/ath10k.build

# Build a makefile

OFILE="tmp/ath10k.build/build_me.sh"
echo "#/bin/bash" > $OFILE
echo "" >> $OFILE
echo "KERNEL_BASE_LINUS=\"$KBL\"" >> $OFILE
echo "" >> $OFILE
echo "make -C \${KERNEL_BASE_LINUS} SUBDIRS=\$PWD modules" >> $OFILE

chmod a+x $OFILE

# Copy some .h files into place.
cp $KBL/drivers/net/wireless/ath/ath.h tmp/ || exit 3
cp $KBL/drivers/net/wireless/ath/regd.h tmp/ || exit 3
cp $KBL/drivers/net/wireless/ath/dfs_pattern_detector.h tmp/ || exit 3
cp $KBL/drivers/net/wireless/ath/spectral_common.h tmp/ || exit 3

# Fix up hacks
HFILE=tmp/ath10k.build/ct_private.h
echo "/* Hacks for building CT firmware */" > $HFILE
if ! grep NUM_NL80211_BANDSS $KBL/net/mac80211/ieee80211_i.h
then
    echo "#define CT_HACK_NEED_IEEE80211_NUM_BANDS" >> $HFILE
fi

if grep ampdu_action $KBL/include/net/mac80211.h
then
    echo "#define CT_HACK_NO_AMPDU_ACTION" >> $HFILE
fi

if ! grep RX_FLAG_ONLY_MONITOR $KBL/include/net/mac80211.h
then
    echo "#define RX_FLAG_ONLY_MONITOR BIT(24)" >> $HFILE
fi

echo "Running $OFILE"
cd tmp/ath10k.build || exit 1
./build_me.sh || exit 2
cd ../..
