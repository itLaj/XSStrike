<h1 align="center">
  <br>
  <a href="https://github.com/s0md3v/XSStrike"><img src="https://image.ibb.co/cpuYoA/xsstrike-logo.png" alt="XSStrike"></a>
  <br>
  XSStrike
  <br>
</h1>

<h4 align="center">Advanced XSS Detection Suite</h4>

<p align="center">
  <a href="https://github.com/s0md3v/XSStrike/releases">
    <img src="https://img.shields.io/github/release/s0md3v/XSStrike.svg">
  </a>
  <a href="https://travis-ci.com/s0md3v/XSStrike">
    <img src="https://img.shields.io/travis/com/s0md3v/XSStrike.svg">
  </a>
  <a href="https://github.com/s0md3v/XSStrike/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/s0md3v/XSStrike.svg">
  </a>
</p>

![multi xss](https://image.ibb.co/gR1ToA/Screenshot-2018-10-27-11-18-43.png)

<p align="center">
  <a href="https://github.com/s0md3v/XSStrike/wiki">XSStrike Wiki</a> •
  <a href="https://github.com/s0md3v/XSStrike/wiki/Usage">Usage</a> •
  <a href="https://github.com/s0md3v/XSStrike/wiki/FAQ">FAQ</a> •
  <a href="https://github.com/s0md3v/XSStrike/wiki/Compatibility-&-Dependencies">Compatibility</a> •
  <a href="https://github.com/s0md3v/XSStrike#gallery">Gallery</a>
</p>

XSStrike is a Cross Site Scripting detection suite equipped with four hand written parsers, an intelligent payload generator, a powerful fuzzing engine and an incredibly fast crawler.

Instead of injecting payloads and checking it works like all the other tools do, XSStrike  analyses the response with multiple parsers and then crafts payloads that are guaranteed to work with context analysis integrated with a fuzzing engine.
Here are some examples of the payloads generated by XSStrike:
```
}]};(confirm)()//\
<A%0aONMouseOvER%0d=%0d[8].find(confirm)>z
</tiTlE/><a%0donpOintErentER%0d=%0d(prompt)``>z
</SCRiPT/><DETAILs/+/onpoINTERenTEr%0a=%0aa=prompt,a()//
```
Apart from that, XSStrike has crawling, fuzzing, parameter discovery, WAF detection capabilities as well. It also scans for DOM XSS vulnerabilities.

### Main Features
- Reflected and DOM XSS Scanning
- Multi-threaded crawling
- Context analysis
- Configurable Core
- Highly Researched Work-flow
- WAF detection & evasion
- Handmade HTML & JavaScript parser
- Powerful fuzzing engine
- Intelligent payload generator
- Complete HTTP Support
- Powered by [Photon](https://github.com/s0md3v/Photon), [Zetanize](https://github.com/s0md3v/zetanize) and [Arjun](https://github.com/s0md3v/Arjun)

> **Note:** This is a beta release and hence prone to bugs. If you find a bug please create an issue.

### Documentation
- [Usage](https://github.com/s0md3v/XSStrike/wiki/Usage)
- [Compatibility & Dependencies](https://github.com/s0md3v/XSStrike/wiki/Compatibility-&-Dependencies)

### FAQ
- [Why XSStrike boasts that it is the most advanced XSS detection suite?](https://github.com/s0md3v/XSStrike/wiki/FAQ#why-xsstrike-boasts-that-it-is-the-most-advanced-xss-detection-suite)
- [How does XSStrike decide if the injection was successful without a browser engine?](https://github.com/s0md3v/XSStrike/wiki/FAQ#how-does-xsstrike-decide-if-the-injection-was-successful-without-a-browser-engine)
- [Does that mean it doesn't have false negatives or false positives?](https://github.com/s0md3v/XSStrike/wiki/FAQ#does-that-mean-it-doesnt-have-false-negatives-or-false-positives)
- [Tool xyz works against the target, while XSStrike doesn't!](https://github.com/s0md3v/XSStrike/wiki/FAQ#tool-xyz-works-against-the-target-while-xsstrike-doesnt)
- [Can I copy it's code?](https://github.com/s0md3v/XSStrike/wiki/FAQ#can-i-copy-its-code)
- [But I will give you credits, is that okay?](https://github.com/s0md3v/XSStrike/wiki/FAQ#but-i-will-give-you-credits-is-that-okay)
- [What if I want to embed it into a proprietary software?](https://github.com/s0md3v/XSStrike/wiki/FAQ#what-if-i-want-to-embed-it-into-a-proprietary-software)

### Gallery
#### DOM XSS
![dom xss](https://image.ibb.co/d1rpvq/Screenshot-2018-10-27-10-59-43.png)
#### Reflected XSS
![multi xss](https://image.ibb.co/gR1ToA/Screenshot-2018-10-27-11-18-43.png)
#### Crawling
![crawling](https://image.ibb.co/iAWNFq/Screenshot-2018-10-27-16-20-36.png)
#### Hidden Parameter Discovery
![arjun](https://image.ibb.co/bOAD5q/Screenshot-2018-10-27-18-16-37.png)
#### Interactive HTTP Headers Prompt
![headers](https://image.ibb.co/jw5NgV/Screenshot-2018-10-27-18-45-32.png)

### Contribution & License
XSStrike v3.0 is in beta phase at present and has been released for public testing.<br>
Useful issues and pull requests are appreciated.

I haven't decided a license yet.
