use Test::More;

use lib 'tools';
use Modsec2LRW qw(parse_vars);

my @out;

@out = parse_vars('ARGS');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '',
		}
	],
	'single var, no modifier or specific'
);

@out = parse_vars('ARGS:foo');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
		}
	],
	'single var with specific element'
);

@out = parse_vars('!ARGS:foo');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
			modifier => '!'
		}
	],
	'single var with specific element and negative modifier'
);

@out = parse_vars('&ARGS');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '',
			modifier => '&'
		}
	],
	'single var with counting modifier'
);

@out = parse_vars('&ARGS:foo');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
			modifier => '&'
		}
	],
	'single var with specific element and counting modifier'
);

@out = parse_vars('ARGS:foo:bar');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo:bar',
		}
	],
	'single var with specific element containing colon'
);

@out = parse_vars('ARGS|ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '',
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two single elements, no modifiers'
);

@out = parse_vars('ARGS:foo|ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two single elements, one specific element'
);

@out = parse_vars('ARGS:foo|ARGS_NAMES:bar');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
		},
		{
			variable => 'ARGS_NAMES',
			specific => 'bar',
		}
	],
	'two single elements, two specific elements'
);

@out = parse_vars('&ARGS:foo|ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
			modifier => '&'
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two single elements, one modifier and one specific element'
);

@out = parse_vars('ARGS:foo|&ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => 'foo',
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
			modifier => '&',
		}
	],
	'two single elements, one modifier, the other with specific element'
);

@out = parse_vars('ARGS:/foo/');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '/foo/',
		}
	],
	'single element with regex specific'
);

@out = parse_vars("ARGS:'/foo/'");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/foo/'",
		}
	],
	'single element with regex specific, quote wrapped'
);

@out = parse_vars("ARGS:/fo'o/");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "/fo'o/",
		}
	],
	'single element with regex specific, quote in specific'
);

@out = parse_vars("ARGS:'/fo'o/'");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/fo'o/'",
		}
	],
	'single element with regex specific, quote wrapped, quote in specific'
);

@out = parse_vars('ARGS:/fo/o/');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '/fo/o/',
		}
	],
	'single element with regex specific, quote wrapped'
);

@out = parse_vars("ARGS:'/fo/o/'");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/fo/o/'",
		}
	],
	'single element with regex specific, quote wrapped, slash in specific'
);

@out = parse_vars('ARGS:/foo|bar/');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '/foo|bar/',
		}
	],
	'single element with regex specific containing pipe'
);

@out = parse_vars("ARGS:'/foo|bar/'");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/foo|bar/'",
		}
	],
	'single element with regex specific containing pipe, quote wrapped'
);

@out = parse_vars('ARGS:/foo/|ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '/foo/',
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific'
);

@out = parse_vars("ARGS:'/foo/'|ARGS_NAMES");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/foo/'",
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific, quote wrapped'
);

@out = parse_vars("ARGS:/fo'o/|ARGS_NAMES");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "/fo'o/",
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific, quote in specific'
);

@out = parse_vars("ARGS:'/fo'o/'|ARGS_NAMES");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/fo'o/'",
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific, quote wrapped, quote in specific'
);

@out = parse_vars('ARGS:/fo/o/|ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '/fo/o/',
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific, slash in specific'
);

@out = parse_vars("ARGS:'/fo/o/'|ARGS_NAMES");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/fo/o/'",
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific, quote wrapped, slash in specific'
);

@out = parse_vars('ARGS:/foo|bar/|ARGS_NAMES');
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => '/foo|bar/',
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific containing pipe'
);

@out = parse_vars("ARGS:'/foo|bar/'|ARGS_NAMES");
is_deeply(
	@out,
	[
		{
			variable => 'ARGS',
			specific => "'/foo|bar/'",
		},
		{
			variable => 'ARGS_NAMES',
			specific => '',
		}
	],
	'two elements, one with regex specific containing pipe, quote wrapped'
);

@out = parse_vars("REQUEST_HEADERS:'/(Content-Length|Transfer-Encoding)/'");
is_deeply(
	@out,
	[
		{
			variable => 'REQUEST_HEADERS',
			specific => "'/(Content-Length|Transfer-Encoding)/'"
		}
	],
	'real-life example from CRSv2 (#185)'
);
done_testing;
