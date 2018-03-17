# flarum-ext-jwt

## Installation
This is a fully plug-n-play solution. All that needs to be done is to add the repository clone url `https://github.com/augustine-institute/flarum-ext-jwt.git` to the repositories list in your flarum `composer.json`. After that you can require the package like so:
```json
{
  "augustineinstitute/flarum-ext-jwt": "<version here>"
}
```

### Example Composer.json
```json
{
  "name": "augustine-institute/community-formed-org",
  "description": "Delightfully simple forum software.",
  "type": "project",
  "keywords": [
    "forum",
    "discussion"
  ],
  "homepage": "http://flarum.org",
  "license": "MIT",
  "authors": [
    {
      "name": "Toby Zerner",
      "email": "toby.zerner@gmail.com"
    },
    {
      "name": "Franz Liedke",
      "email": "franz@develophp.org"
    }
  ],
  "support": {
    "issues": "https://github.com/dfsklar/core/issues",
    "source": "https://github.com/dfsklar/flarum",
    "docs": "http://flarum.org/docs"
  },
  "require": {
    "flarum/core": "dev-master",
    "flarum/flarum-ext-tags": "dev-some-styles",
    "flarum/flarum-ext-subscriptions": "dev-master",
    "flarum/flarum-ext-mentions": "dev-master",
    "flarum/flarum-ext-likes": "dev-master",
    "flarum/flarum-ext-english": "dev-master",
    "augustineinstitute/flarum-ext-jwt": "*@dev",
    "flarum/flarum-ext-akismet": "^0.1.0",
    "flarum/flarum-ext-approval": "^0.1.0",
    "flarum/flarum-ext-auth-facebook": "^0.1.0",
    "flarum/flarum-ext-auth-github": "^0.1.0",
    "flarum/flarum-ext-auth-twitter": "^0.1.0",
    "flarum/flarum-ext-bbcode": "^0.1.0",
    "flarum/flarum-ext-emoji": "^0.1.0",
    "flarum/flarum-ext-flags": "^0.1.0",
    "flarum/flarum-ext-lock": "^0.1.0",
    "flarum/flarum-ext-markdown": "^0.1.0",
    "flarum/flarum-ext-pusher": "^0.1.0",
    "flarum/flarum-ext-sticky": "^0.1.0",
    "flarum/flarum-ext-suspend": "^0.1.0",
    "flarum/flarum-ext-embed": "^0.1.0"
  },
  "repositories": [
    {
      "type": "vcs",
      "url": "git@github.com:augustine-institute/flarum_core.git"
    },
    {
      "type": "vcs",
      "url": "git@github.com:augustine-institute/flarum-ext-jwt.git"
    },
    {
      "type": "github",
      "url": "https://github.com/augustine-institute/flarum-ext-tags"
    },
    {
      "type": "vcs",
      "url": "https://github.com/dfsklar/flarum-ext-subscriptions"
    },
    {
      "type": "vcs",
      "url": "https://github.com/dfsklar/flarum-ext-mentions"
    },
    {
      "type": "vcs",
      "url": "https://github.com/dfsklar/flarum-ext-likes"
    },
    {
      "type": "vcs",
      "url": "https://github.com/dfsklar/flarum-ext-english"
    }
  ],
  "require-dev": {
    "franzl/studio": "^0.11.0"
  },
  "config": {
    "preferred-install": "dist"
  },
  "minimum-stability": "dev",
  "prefer-stable": true
}
```

## Usage
I have created this with some environment variables that can be set to adjust functionality. Here is the list: 


| API_SECRET | **REQUIRED** This is the secret use on the api to create the JWT token. This must be set |
| JWT_API_ONLY | Only check on requests to the flarum api routes |
| JWT_FORUM_ONLY | Only check on request to the standard forum routes by regular users |
| JWT_CHECK_COOKIE | Check for a cookie at all? |
| ENVIRONMENT | **REQUIRED** This should be one of the following: local, stage, beta, production |
| JWT_ENFORCE | Should be enforced at all? If false it will allow users through even if the token or secret doesn't exit or is invalid |
