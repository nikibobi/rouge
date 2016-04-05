# -*- coding: utf-8 -*- #

describe Rouge::Lexers::FSharp do
  let(:subject) { Rouge::Lexers::FSharp.new }

  describe 'guessing' do
    include Support::Guessing

    it 'guesses by filename' do
      assert_guess filename: 'foo.fs'
      assert_guess filename: 'bar.fsi'
      assert_guess filename: 'baz.fsx'
    end

    it 'guesses by mimetype' do
      assert_guess mimetype: 'application/fsharp-script'
      assert_guess mimetype: 'text/x-fsharp'
      assert_guess mimetype: 'text/x-fsi'
    end
  end
end
