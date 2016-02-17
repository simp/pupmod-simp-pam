require 'spec_helper'

describe 'pam::access::manage' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        let(:title){ 'test' }
        let(:params){{
          :users => 'user1 user2',
          :origins => ['foo.bar.baz','bar.baz.foo'],
          :order => '1'
        }}

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_concat_fragment("pam_access+#{params[:order]}.#{title}.access").with_content(<<-EOM.gsub(/^\s+/,'')
          + : #{params[:users]} : #{params[:origins].join(' ')}
          EOM
        )}

        context 'with_comment' do
          let(:params){{
            :users => 'user1 user2',
            :origins => ['foo.bar.baz','bar.baz.foo'],
            :order => '1',
            :comment => "foo\nbar\nbaz"
          }}

          it { is_expected.to create_concat_fragment("pam_access+#{params[:order]}.#{title}.access").with_content(<<-EOM.gsub(/^\s+/,'')
            # foo
            # bar
            # baz
            + : #{params[:users]} : #{params[:origins].join(' ')}
            EOM
          )}
        end
      end
    end
  end
end
