##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'SS7 ProvideSubscriberInfo',
      'Description'   => %q{

      },
      'Author'        => [
          'Anwar Mohamed <anwarelmakrahy[at]gmail.com>',
          'Loay Abd ElRazek <loay.razek[at]gmail.com>'
        ],
      'License'       => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('StrKey', [ false, 'Description', 'Default' ]),
        OptBool.new('BoolKey', [ false, 'Description', false ]),
        OptInt.new('IntKey', [ true, 'Description', 300 ])
      ], self.class)
  end

  def run
    print_status("Starting SS7 Auxiliary")
  end
end