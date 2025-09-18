---
layout: page
title: About
description: Nothing can change your mind
keywords: bsauce
comments: true
menu: 关于
permalink: /about/
---

我是bsauce，某高校小青椒一枚，助理研究员。

喜欢足球、跑步、户外。

学习使我头秃。

不学怎么办呀，论文又发不出来~~

欢迎对**Linux内核漏洞挖掘与利用**的同学联系我，一起研究漏洞实践利用、发论文~~❤
或者，来读研？（虽然目前还没有招硕士的资格~）

Email: bsauce0@outlook.com

## 联系

<ul>
{% for website in site.data.social %}
<li>{{website.sitename }}：<a href="{{ website.url }}" target="_blank">@{{ website.name }}</a></li>
{% endfor %}
{% if site.url contains 'mazhuang.org' %}
<li>
微信公众号：<br />
<img style="height:192px;width:192px;border:1px solid lightgrey;" src="{{ assets_base_url }}/assets/images/qrcode.jpg" alt="闷骚的程序员" />
</li>
{% endif %}
</ul>


## Skill Keywords

{% for skill in site.data.skills %}
### {{ skill.name }}
<div class="btn-inline">
{% for keyword in skill.keywords %}
<button class="btn btn-outline" type="button">{{ keyword }}</button>
{% endfor %}
</div>
{% endfor %}

