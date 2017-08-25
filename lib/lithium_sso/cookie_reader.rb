module LithiumSSO
  class CookieReader

    def initialize(secret_key)
      @secret_key = secret_key
    end

    def read(cookie)
      _, iv, encrypted = *cookie.match(/~2(.+)~(.+)/)

      raw_data = decrypt(encrypted, iv)

      lithium_version, server_id,
      timestamp1, timestamp2, # ???
      user_agent, referer, ip_address,
      lithium_domain, lithium_id,
      user_id, user_login, user_email, * = raw_data.gsub(/(^Li\|)|(iL$)/, '').split('|')

      {
        external_id: user_id,
        name: user_login,
        email: user_email
      }
    end

    private

    def decrypt(s, iv)
      s1 = s.gsub('-', '+').gsub('_', '/').gsub('.', '=')
      s2 = Base64.strict_decode64(s1)
      s3 =  Mcrypt.new(:rijndael_128, :cbc, @secret_key.split.pack('H*'), iv).decrypt(s2)
      s4 = Zlib::Inflate.inflate(s3)
    end

  end
end



__END__


LiSSOv1.5
127.0.0.1-32F8EF1EC1FFE040589CF061D4ABDABC
1503651554001
1503651554000
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.101 Safari/537.36

127.0.0.1
.leroymerlin.ru
leroy_community
1000
Alexey Neyman
alexey@shoppilot.ru
profile.url_homepage=http://leroymerlin.ru/home
roles.grant=Moderator

$raw_string .= $this->lithium_version;
$raw_string .= $this->server_id;
$raw_string .= number_format( $this->tsid, 0, '', '' );
$raw_string .= time() . "000";
$raw_string .= $this->get_token_safe_string($req_user_agent);
$raw_string .= $this->get_token_safe_string($req_referer);
$raw_string .= $this->get_token_safe_string($req_remote_addr);
$raw_string .= $this->client_domain;
$raw_string .= $this->client_id;
$raw_string .= $this->get_token_safe_string($unique_id);
$raw_string .= $this->get_token_safe_string($login);
$raw_string .= $this->get_token_safe_string($email);
$raw_string .= $settings_string;
