require 'spec_helper'

describe 'pam::access::manage' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :lsbdistrelease => '6.5',
    :lsbmajdistrelease => '6'
  }}
  let(:title){ 'test' }
  let(:params){{
    :users => 'user1 user2',
    :origins => ['foo.bar.baz','bar.baz.foo'],
    :order => '1'
  }}

  it { should compile.with_all_deps }

  it { should create_concat_fragment("pam_access+#{params[:order]}.#{title}.access").with_content(<<-EOM.gsub(/^\s+/,'')
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
    
    it { should create_concat_fragment("pam_access+#{params[:order]}.#{title}.access").with_content(<<-EOM.gsub(/^\s+/,'')
      # foo
      # bar
      # baz
      + : #{params[:users]} : #{params[:origins].join(' ')}
      EOM
    )}
  end
end
