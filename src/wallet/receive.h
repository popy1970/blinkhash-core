// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLINKHASH_WALLET_RECEIVE_H
#define BLINKHASH_WALLET_RECEIVE_H

#include <amount.h>
#include <wallet/ismine.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
};

#endif // BLINKHASH_WALLET_RECEIVE_H
