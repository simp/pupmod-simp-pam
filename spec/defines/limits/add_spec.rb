require 'spec_helper'

describe 'pam::limits::add' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :lsbdistrelease => '6.5',
    :lsbmajdistrelease => '6'
  }}
  let(:title){ 'test' }
  let(:params){{
    :domain => '*',
    :item => 'core',
    :value => '0',
    :type => '-',
    :order => '1'
  }}

  it { should compile.with_all_deps }

  it { should create_concat_fragment("pam_limits+#{params[:order]}.#{title}.limit").with_content(
    /#{Regexp.escape(params[:domain])}\s#{params[:type]}\s#{params[:item]}\s#{params[:value]}/
  )}
end
