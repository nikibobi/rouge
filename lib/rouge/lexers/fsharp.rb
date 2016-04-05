# -*- coding: utf-8 -*- #

module Rouge
  module Lexers
    class FSharp < RegexLexer
      tag 'fsharp'
      aliases 'f#'
      filenames '*.fs', '*.fsi', '*.fsx'
      mimetypes 'application/fsharp-script', 'text/x-fsharp', 'text/x-fsi'

      title 'F#'
      desc 'a functional language for .NET'

      keywords = %w(
        abstract as assert base begin class default
        delegate do! do done downcast downto elif else
        end exception extern false finally for function
        fun global if inherit inline interface internal
        in lazy let! let match member module mutable
        namespace new null of open override private public
        rec return! return select static struct then to
        true try type upcast use! use val void when
        while with yield! yield
      )

      keywords += %w(
        atomic break checked component const constraint
        constructor continue eager event external fixed
        functor include method mixin object parallel
        process protected pure sealed tailcall trait
        virtual volatile
      )

      keyopts = %w(
        != # && & ( ) * + , -.
        -> - .. . :: := :> : ;; ; <-
        <] < >] > ?? ? [< [| [ ]
        _ ` { |] | } ~ <@@ <@ = @> @@>
      )

      operators = /[!$%&*+\.\/:<=>?@^|~-]/
      word_operators = ['and','or','not']
      prefix_syms = /[!?~]/
      infix_syms = /[=<>@^|&+\*\/$%-]/
      primitives = q%(
        sbyte byte char nativeint unativeint float32 single
        float double int8 uint8 int16 uint16 int32
        uint32 int64 uint64 decimal unit bool string
        list exn obj enum
      )

      state :escape-sequence do
        rule /\\[\\"\'ntbrafv]/, Str::Escape
        rule /\\[0-9]{3}/, Str::Escape
        rule /\\u[0-9a-fA-F]{4}/, Str::Escape
        rule /\\U[0-9a-fA-F]{8}/, Str::Escape
      end

      state :root do
        rule /\s+/m, Text
        rule /\(\)|\[\]/, Name::Builtin::Pseudo
        rule /\b(?<!\.)([A-Z][\w\']*)(?=\s*\.)/, Name::Namespace, :dotted
        rule /\b([A-Z][\w\']*)/, Name
        rule %r(///.*?\n), Str::Doc
        rule %r(//.*?\n), Comment::Single
        rule /\(\*(?!\))/, Comment, :comment

        rule /@"/, Str, :lstring
        rule /"""/, Str, :tqs
        rule /"/, Str, :string

        rule /\b(open|module)(\s+)([\w.]+)/ do
          groups Keyword, Text, Name::Namespace
        end
        rule /\b(let!?)(\s+)(\w+)/ do
          groups Keyword, Text, Name::Variable
        end
        rule /\b(type)(\s+)(\w+)/ do
          groups Keyword, Text, Name::Class
        end
        rule /\b(member|override)(\s+)(\w+)(\.)(\w+)/ do
          groups Keyword, Text, Name, Punctuation, Name::Function
        end
        rule /\b(#{keywords.join('|')})\b/, Keyword
        rule /``([^`\n\r\t]|`[^`\n\r\t])+``/, Name
        rule /(#{keyopts.join('|')})/
        rule /(#{infix_syms}|#{prefix_syms})?#{operators}/, Operator
        rule /\b(#{word_operators.join('|')})\b/, Operator::Word
        rule /\b(#{primitives.join('|')})\b/, Keyword::Type
        rule /#[ \t]*(if|endif|else|line|nowarn|light|\d+)\b.*?\n/, Comment::Preproc

        rule /[^\W\d][\w']*/, Name

        rule /\d[\d_]*[uU]?[yslLnQRZINGmM]?/, Num::Integer
        rule /0[xX][\da-fA-F][\da-fA-F_]*[uU]?[yslLn]?[fF]?/, Num::Hex
        rule /0[oO][0-7][0-7_]*[uU]?[yslLn]?/, Num::Oct
        rule /0[bB][01][01_]*[uU]?[yslLn]?/, Num::Bin
        rule /-?\d[\d_]*(.[\d_]*)?([eE][+\-]?\d[\d_]*)[fFmM]?/, Num::Float

        rule /'(?:(\\[\\\"'ntbr ])|(\\[0-9]{3})|(\\x[0-9a-fA-F]{2}))'B?/, Str::Char
        rule /'.'/, Str::Char
        rule /'/, Keyword

        rule /@?"/, Str::Double, :string
        rule /[~?][a-z][\w\']*:/, Name::Variable
      end

      state :dotted do
        rule /\s+/, Text
        rule /\./, Punctuation
        rule /[A-Z][\w\']*(?=\s*\.)/, Name::Namespace
        rule /[A-Z][\w\']*/, Name, :pop!
        rule /[a-z_][\w\']*/, Name, :pop!
        rule(//) { pop! }
      end

      state :comment do
        rule /[^(*)@"]+/, Comment
        rule /\(\*/, Comment, :push
        rule /\*\)/, Comment, :pop!
        rule /@"/, Str, :lstring
        rule /"""/, Str, :tqs
        rule /"/, Str, :string
        rule /[(*)@]/, Comment
      end

      state :string do
        rule /[^\\"]+/, Str
        mixin :escape-sequence
        rule /\\\n/, Str
        rule /\n/, Str
        rule /"B?/, Str, :pop!
      end

      state :lstring do
        rule /[^"]+/, Str
        rule /\n/, Str
        rule /""/, Str
        rule /"B?/, Str, :pop!
      end

      state :tqs do
        rule /[^"]+/, Str
        rule /\n/, Str
        rule /"""B?/, Str, :pop!
        rule /"/, Str
      end
    end
  end
end
