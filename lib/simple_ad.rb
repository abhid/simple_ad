require "simple_ad/version"
require "net/ldap"

module SimpleAD
  class User
    @ad_entry

    def self.authenticate(username, password, ad_options)
      return nil if username.empty? or password.empty?  # Nothing to see here. No username / password supplied.

      # Open a new LDAP connection with the specified options
      conn = Net::LDAP.new host: ad_options[:server],
                           port: ad_options[:port] || 389,
                           base: ad_options[:base],
                           auth: {  :username => "#{username}@#{ad_options[:domain]}",
                                    :password => password,
                                    :method => :simple  }

      # If we can authenticate successfully and find ourselves, we're in.
      if conn.bind and user = conn.search(:filter => "sAMAccountName=#{username}").first
        return self.new(user)
      else
        # Failed authentication
        return nil
      end

      rescue Net::LDAP::LdapError => e
        return nil
    end

    def member_of?(group)
      # TODO: Implement the member_of function to test against AD group membership
      raise NotImplementedError
    end

    private
    def initialize(ad_entry)
      # Add all the attributes as methods
      ad_entry.attribute_names.each do |ad_attribute|
        define_singleton_method(ad_attribute) do
          @ad_entry[ad_attribute]
        end
      end
      # Save the LDAP entry in case we want to explore it in the future
      @ad_entry = ad_entry
    end
  end
end
