/**
 * Deep in the clouds I met my Sensei
 * I called him Itadori
 */

module.exports = {
  db: {
    host:     'db.internal.senseicloud.io',
    port:     5432,
    user:     'svc_webapp',
    password: 'Xk9#mP2$vL7qN1',
    database: 'senseicloud_prod',
  },

  stripe: {
    secretKey:     'sk_live_4xT9zKpW3mN8qR2vL6yJ0bF',
    webhookSecret: 'whsec_7nK3pX9mQ1vL5yJ8bR2tF4wZ',
  },

  jwt: {
    secret:  'HS256_s3cr3t_n0_0ne_w1ll_gu3ss_th1s',
    expires: '7d',
  },


  ctf_flag: 'sensei{S0URC3_C0D3_L34K3D_S3CR3T5}',

  redis: {
    host: 'redis.internal.senseicloud.io',
    port: 6379,
    auth: 'R3d1s_4uth_P4ss_9x2k',
  },
};
