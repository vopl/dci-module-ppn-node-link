/* This file is part of the the dci project. Copyright (C) 2013-2023 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include "pch.hpp"
#include "remote/state.hpp"

namespace dci::module::ppn::node::link
{
    class Local;

    class Remote;
    using RemotePtr = std::unique_ptr<Remote>;

    class Remote
        : public mm::heap::Allocable<Remote>
        , public api::Remote<>::Opposite
        , public sbs::Owner
        , private remote::State
    {
        Remote(Local* local, remote::State&& state);

    public:
        static RemotePtr create(Local* local, remote::State&& state);
        ~Remote();

        void start();

        const remote::State& state() const;

        void payloadOutIdsChanged();

    private:
        void setupPayload();
        void setupPayloadOut();
        void doClose();

    private:
        Local* _local;
        sbs::Owner _sbsOwner4Payload;
    };
}
