'use strict';

const ip = require('ip');
const boom = require('boom');
const castArray require('lodash.castarray');

exports.register = function register(server, options, next) {
  server.auth.scheme('ip-whitelist', function (server, config) {
    return {
      ipMatch(address, remoteAddress) {
        const parts = address.split('/');
        try {
          if (parts.length === 2) {
            if (ip.cidrSubnet(address).contains(remoteAddress)) {
              return true;
            }
          } else if (parts.length === 1) {
            if (ip.isEqual(address, remoteAddress)) {
              return true;
            }
          }
          return false;
        } catch (e) {
          server.log(['status', 'ipfilter', 'info'], {
            tmpl: 'Unrecognized filter address: <%= address %>',
            address: address,
          });
        }
      },
      authenticate: function (request, reply) {
        const remoteAddress = request.info.remoteAddress;
        const allowList = castArray(config.getAllowList() || []);
        const denyList = castArray(config.getDenyList() || []);

        let allow = true;
        denyList.some(address => {
          if (address === '_all' || this.ipMatch(address, remoteAddress)) {
            allow = false;
            server.log(['status', 'ipfilter', 'debug'], {
              tmpl: 'Deny remote address: <%= remoteAddress %> by <%= address %>',
              address: address,
              remoteAddress: remoteAddress,
            });
            return true;
          }
        });
        allowList.some(address => {
          if (address === '_all' || this.ipMatch(address, remoteAddress)) {
            allow = true;
            server.log(['status', 'ipfilter', 'debug'], {
              tmpl: 'Allow remote address: <%= remoteAddress %> by <%= address %>',
              address: address,
              remoteAddress: remoteAddress,
            });
            return true;
          }
        });

        if (allow) {
          reply.continue({
            credentials: remoteAddress,
          });
        } else {
          reply(boom.unauthorized(`${remoteAddress} is not a valid IP`));
        }
      }
    };
  });
  return next();
}

register.attributes = {
  pkg: require('../package.json'),
};

export default {
  register,
};
