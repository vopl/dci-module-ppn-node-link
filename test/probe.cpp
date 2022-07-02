/* This file is part of the the dci project. Copyright (C) 2013-2022 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include <dci/test.hpp>
#include <dci/host.hpp>
#include <dci/poll.hpp>
#include <dci/crypto.hpp>
#include <dci/utils/b2h.hpp>

using namespace dci;
using namespace dci::host;
using namespace dci::cmt;

/////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
TEST(module_ppn_node_link, probe)
{
//    Array<uint8, 32> priv, publ;
//    Array<uint8, 32> priv1, publ1;
//    real64 best = 256;

//    for(std::size_t i{0}; ; ++i)
//    {
//        crypto::rnd::generate(priv.data(), priv.size());
//        dci::crypto::curve25519::basepoint(priv.data(), publ.data());

//        real64 d = log2(utils::id2Real(publ));

//        if(d < best)
//        {
//            best = d;
//            priv1 = priv;
//            publ1 = publ;

//            LOGD(utils::b2h(publ)<<", "<<i<<", "<<best);
//        }
//    }
}
