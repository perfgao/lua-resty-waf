use Test::More;
use Test::Warn;
use Test::MockModule;

use Cwd qw(cwd);
my $pwd = cwd();

use lib 'tools';
use Modsec2LRW qw(translate_actions);

my $Mock = Test::MockModule->new('Modsec2LRW');

$Mock->mock(translate_macro => sub {
	my ($pattern) = @_;

	return "$pattern-mocked";
});

my $translation;

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'allow'
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		action => 'ACCEPT'
	},
	'translate allow'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'block'
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		action => 'DENY'
	},
	'translate block'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'deny'
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		action => 'DENY'
	},
	'translate deny'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'pass'
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		action => 'IGNORE'
	},
	'translate pass'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'expirevar',
				value  => 'foo.bar=60',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			expirevar => [
				{
					col  => 'foo',
					key  => 'bar',
					time => 60,
				}
			]
		}
	},
	'translate expirevar with numeric expire time'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'id',
				value  => 12345,
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		id => 12345,
	},
	'translate id'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'initcol',
				value  => 'IP=%{REMOTE_ADDR}',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			initcol => { IP => '%{REMOTE_ADDR}' }
		}
	},
	'translate initcol'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'logdata',
				value  => 'data',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		logdata => 'data-mocked',
	},
	'translate logdata'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'msg',
				value  => 'data',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		msg => 'data',
	},
	'translate msg'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'noauditlog',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			nolog => 1,
		}
	},
	'translate noauditlog'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'nolog',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			nolog => 1,
		}
	},
	'translate nolog'
);

$translation = { opts => { nolog => 1 } };
translate_actions(
	{
		actions => [
			{
				action => 'auditlog',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {},
	},
	'translate auditlog (deletes nolog)'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'auditlog',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{},
	'translate auditlog (does not autovify opts)'
);

$translation = { opts => { nolog => 1 } };
translate_actions(
	{
		actions => [
			{
				action => 'log',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {},
	},
	'translate log (deletes nolog)'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'log',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{},
	'translate log (does not autovify opts)'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'phase',
				value  => 'access',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		phase => 'access',
	},
	'translate phase'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'skip',
				value  => 1,
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		skip => 1,
	},
	'translate skip'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'skipAfter',
				value  => 1,
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		skip_after => 1,
	},
	'translate skipAfter'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'setvar',
				value  => 'IP.foo=bar',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			setvar => [
				{
					col   => 'IP',
					key   => 'foo',
					value => 'bar',
				}
			]
		}
	},
	'translate setvar with string value'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'setvar',
				value  => 'IP.foo=60',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			setvar => [
				{
					col   => 'IP',
					key   => 'foo',
					value => 60,
				}
			]
		}
	},
	'translate setvar with integer value'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'setvar',
				value  => 'IP.foo=+60',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			setvar => [
				{
					col   => 'IP',
					key   => 'foo',
					value => '60',
					inc   => 1,
				}
			]
		}
	},
	'translate setvar with string value'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'setvar',
				value  => 'IP.foo.bar=60',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			setvar => [
				{
					col   => 'IP',
					key   => 'foo.bar',
					value => 60,
				}
			]
		}
	},
	'translate setvar with key having a dot'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 'setvar',
				value  => '!IP.foo',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			deletevar => [
				{
					col   => 'IP',
					key   => 'foo',
				}
			]
		}
	},
	'translate setvar with integer value'
);

$translation = {};
warning_like
	{
		translate_actions(
			{
				actions => [
					{
						action => 'setvar',
						value  => 'IP.foo',
					}
				]
			},
			$translation,
			undef
		);
	}
	qr/No assignment in setvar, but not a delete\?/,
	'warn when setvar sets not value, but does not prepend !'
;

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 't',
				value  => 'none',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{},
	'translate t:none'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 't',
				value  => 'length',
			}
		]
	},
	$translation,
	undef
);
is_deeply(
	$translation,
	{
		opts => {
			transform => [ qw(length) ]
		}
	},
	'translate t:length'
);

$translation = {};
warning_is
	{
		translate_actions(
			{
				actions => [
					{
						action => 't',
						value  => 'foo',
					}
				]
			},
			$translation,
			undef
		);
	}
	'Cannot perform transform foo',
	'warn on invalid transform'
;

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 't',
				value  => 'foo',
			}
		]
	},
	$translation,
	1
);
is_deeply(
	$translation,
	{},
	'do not warn on translation fail when silent is set'
);

$translation = {};
translate_actions(
	{
		actions => [
			{
				action => 't',
				value  => 'length',
			},
			{
				action => 't',
				value  => 'foo',
			}
		]
	},
	$translation,
	1
);
is_deeply(
	$translation,
	{
		opts => {
			transform => [ qw(length) ]
		}
	},
	'once transform translation failure does not prevent another'
);

TODO: {
	local $TODO = "warn on invalid action (unless silent)";

	$translation = {};
	warning_like
		{
			translate_actions(
				{
					actions => [
						{
							action => 'foo',
						}
					]
				},
				$translation,
				undef
			);
		}
		qr/Invalid action foo/,
		'warn on invalid action'
	;

	$translation = {};
	translate_actions(
		{
			actions => [
				{
					action => 'foo',
				}
			]
		},
		$translation,
		1
	);
	is_deeply(
		$translation,
		{},
		'do not warn on translation fail when silent is set'
	);
}

done_testing;
