/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "pch.hpp"
#include "handshake.hpp"
#include "local.hpp"

namespace dci::module::ppn::node::link
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Handshake::Handshake(Local* local, apit::Channel<>&& channel, bool byConnect)
        : _local(local)
        , _state(std::move(channel), byConnect)
        , _completion()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Handshake::~Handshake()
    {
        flush();

        _state.reset();

        if(_completion.charged() && !_completion.resolved())
        {
            _completion.resolveCancel();
        }
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    cmt::Future<api::Remote<>> Handshake::completion()
    {
        dbgAssert(_completion.charged());
        return _completion.future();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Handshake::start()
    {
        _completion.future().then() += this * [this](auto in)
        {
            if(in.resolvedException() || in.resolvedCancel())
            {
                _local->handshakeFailed(this);
            }
        };

        _state._channel->failed() += this * [this](ExceptionPtr e)
        {
            if(_completion.charged() && !_completion.resolved())
            {
                _completion.resolveException(exception::buildInstance<api::ChannelFailure>(e));
            }
        };

        _state._channel->closed() += this * [this]()
        {
            if(_completion.charged() && !_completion.resolved())
            {
                _completion.resolveException(exception::buildInstance<api::ChannelFailure>("closed"));
            }
        };

        _local->createServiceFromHost<idl::stiac::Protocol<>>().then() += this * [this](auto in)
        {
            if(in.resolvedValue())
            {
                if(!_completion.charged() || _completion.resolved())
                {
                    //too late
                    return;
                }

                dbgAssert(!_state._stiacProto);
                _state._stiacProto = in.detachValue();
                setupProtocol();
                return;
            }
            else if(in.resolvedException())
            {
                LOGW("unable to obtain stiac protocol service from local host: " << exception::toString(in.detachException()));
            }
            else if(in.resolvedCancel())
            {
                LOGW("unable to obtain stiac protocol service from local host: canceled");
            }

            if(_completion.charged() && !_completion.resolved())
            {
                if(in.resolvedException())
                {
                    _completion.resolveException(exception::buildInstance<api::RequirementsFailure>(in.detachException(), "unable to obtain stiac protocol service from local host"));
                    return;
                }
                _completion.resolveException(exception::buildInstance<api::RequirementsFailure>("unable to obtain stiac protocol service from local host"));
            }
            return;
        };
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Handshake::setupProtocol()
    {
        dbgAssert(_state._stiacProto);

        _state._stiacProto->setAutoPumping(idl::stiac::protocol::AutoPumping::delayed);

        dbgAssert(!_state._stiacLocalEdge);
        _state._stiacLocalEdge = idl::stiac::LocalEdge<>(idl::interface::Initializer{});
        _state._stiacProto->setLocalEdge(_state._stiacLocalEdge.opposite());

        _state._stiacProto->setRemoteEdge(_state._channel);

        _state._stiacProto->setRequirements(
                    idl::stiac::protocol::Requirements::ciphering, idl::stiac::protocol::Requirements::compression,
                    idl::stiac::protocol::Requirements::ciphering);
        _state._stiacProto->setAuthPrologue("dci/module/ppn/link/0");
        _state._stiacProto->setAuthLocal(_local->key());

        _state._stiacProto->remoteAuthChanged() += this * [this](const idl::stiac::protocol::PublicKey& remotePublicKey)
        {
            crypto::blake2b(remotePublicKey.data(), remotePublicKey.size(), _state._id.data(), _state._id.size());
        };

        _state._stiacProto->fail() += this * [this](const ExceptionPtr& e)
        {
            if(_completion.charged() && !_completion.resolved())
            {
                _completion.resolveException(exception::buildInstance<api::ProtocolFailure>(e));
            }
        };

        {
            _state._stiacLocalEdge->got() += this * [this](idl::Interface&& i)
            {
                if(_completion.charged() && !_completion.resolved())
                {
                    if(i.mdLid() != api::remote::Payload<>::lid())
                    {
                        _completion.resolveException(exception::buildInstance<api::RemoteFailure>("unknown interface received from remote instead of Payload"));
                        return cmt::readyFuture<void>();
                    }

                    _state._payload = std::move(i);
                    _local->handshakeCompleted(this, std::move(_state), std::move(_completion));
                }
                else
                {
                    _state.reset();
                }

                return cmt::readyFuture<void>();
            };
        }

        api::remote::Payload<> payload{_state._payloadOut.init2()};
        if(!payload)
        {
            if(_completion.charged() && !_completion.resolved())
            {
                _completion.resolveException(exception::buildInstance<api::RequirementsFailure>("Payload must be provided before useful working"));
            }
            return;
        }

        idl::ILid payloadIlid = payload.lid();

        apit::Channel<>         channel {_state._channel};
        idl::stiac::Protocol<>  stiacProto {_state._stiacProto};
        idl::stiac::LocalEdge<> stiacLocalEdge {_state._stiacLocalEdge};

        stiacProto->start();
        stiacLocalEdge->optimisticPutConcrete(std::move(payload), payloadIlid);
        channel->unlockInput();
    }
}
