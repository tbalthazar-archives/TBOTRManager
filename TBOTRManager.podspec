Pod::Spec.new do |s|
  s.name = 'TBOTRManager'
  s.version = '0.0.1'
  s.platform = :ios, '7.0'
  #s.license = { :type => 'BSD', :file => 'copying.txt' }
  #s.summary = ''
  s.homepage = 'https://github.com/tbalthazar/TBOTRManager'
  s.author = { 'Thomas Balthazar' => 'xxx' }
  s.source = { :git => 'https://github.com/tbalthazar/TBOTRManager.git' } #, :tag => '3.6.2' }
  #s.resources = [ '**/*.{xcdatamodel,xcdatamodeld}']

  s.description = ''
  s.requires_arc = true

  #s.public_header_files = 'TBOTRManager/*.h'
  #spec.source_files = "Classes/**/*.{h,m}"
  spec.source_files = "TBOTRManager/**/*.{h,m}"
end