# msprobe

+ [About](#about)
+ [Installing](#installing)
+ [Usage](#usage)
+ [Examples](#examples)
+ [Acknowledgements](#acknowledgements)



## About <a name = "about"></a>
Finding all things on-prem Microsoft for password spraying and enumeration. 






### Installing <a name = "installing"></a>

Install the project using [pipx](https://pypa.github.io/pipx/installation/)

```
pipx install git+https://github.com/puzzlepeaches/msprobe.git
```




## Usage <a name = "usage"></a>

The tool has four different modules that assist with the discovery of on-prem Microsoft products:

* Exchange
* RD Web
* ADFS
* Skype for Business

The help menu and supported modules are shown below:

```
Usage: msprobe [OPTIONS] COMMAND [ARGS]...

  Find Microsoft Exchange, RD Web, ADFS, and Skype instances

Options:
  --help  Show this message and exit.

Commands:
  adfs   Find Microsoft ADFS servers
  exch   Find Microsoft Exchange servers
  full   Find all Microsoft supported by msprobe
  rdp    Find Microsoft RD Web servers
  skype  Find Microsoft Skype servers
```




## Examples <a name = "examples"></a>

Find ADFS servers associated with apex domain:

```
msprobe adfs acme.com
```

Find RD Web servers associated with apex domain with verbose output:

```
msprobe rdp acme.com -v
```

Find all Microsoft products hostsed on-prem for a domain:

```
msprobe full acme.com
```




## Acknowledgements <a name = "acknowledgements"></a>
- [@p0dalirius](https://twitter.com/intent/follow?screen_name=podalirius_) for [RDWArecon](https://github.com/p0dalirius/RDWArecon) 
- [@b17zr](https://twitter.com/b17zr) for the `ntlm_challenger.py` script
