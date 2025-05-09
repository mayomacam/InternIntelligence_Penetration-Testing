var Lu = Object.create;
var _e = Object.defineProperty;
var Tu = Object.getOwnPropertyDescriptor;
var $u = Object.getOwnPropertyNames;
var Iu = Object.getPrototypeOf,
    Mu = Object.prototype.hasOwnProperty;
var Fu = (n, t, e) => t in n ? _e(n, t, {
    enumerable: !0,
    configurable: !0,
    writable: !0,
    value: e
}) : n[t] = e;
var qu = (n, t) => () => (n && (t = n(n = 0)), t);
var _ = (n, t) => () => (t || n((t = {
        exports: {}
    }).exports, t), t.exports),
    Se = (n, t) => {
        for (var e in t) _e(n, e, {
            get: t[e],
            enumerable: !0
        })
    },
    Vo = (n, t, e, i) => {
        if (t && typeof t == "object" || typeof t == "function")
            for (let r of $u(t)) !Mu.call(n, r) && r !== e && _e(n, r, {
                get: () => t[r],
                enumerable: !(i = Tu(t, r)) || i.enumerable
            });
        return n
    };
var Wo = (n, t, e) => (e = n != null ? Lu(Iu(n)) : {}, Vo(t || !n || !n.__esModule ? _e(e, "default", {
        value: n,
        enumerable: !0
    }) : e, n)),
    Bu = n => Vo(_e({}, "__esModule", {
        value: !0
    }), n);
var at = (n, t, e) => (Fu(n, typeof t != "symbol" ? t + "" : t, e), e),
    Pu = (n, t, e) => {
        if (!t.has(n)) throw TypeError("Cannot " + e)
    };
var ot = (n, t, e) => {
    if (t.has(n)) throw TypeError("Cannot add the same private member more than once");
    t instanceof WeakSet ? t.add(n) : t.set(n, e)
};
var L = (n, t, e) => (Pu(n, t, "access private method"), e);
var Is = _((Tb, Fh) => {
    Fh.exports = {
        Aacute: "\xC1",
        aacute: "\xE1",
        Abreve: "\u0102",
        abreve: "\u0103",
        ac: "\u223E",
        acd: "\u223F",
        acE: "\u223E\u0333",
        Acirc: "\xC2",
        acirc: "\xE2",
        acute: "\xB4",
        Acy: "\u0410",
        acy: "\u0430",
        AElig: "\xC6",
        aelig: "\xE6",
        af: "\u2061",
        Afr: "\u{1D504}",
        afr: "\u{1D51E}",
        Agrave: "\xC0",
        agrave: "\xE0",
        alefsym: "\u2135",
        aleph: "\u2135",
        Alpha: "\u0391",
        alpha: "\u03B1",
        Amacr: "\u0100",
        amacr: "\u0101",
        amalg: "\u2A3F",
        amp: "&",
        AMP: "&",
        andand: "\u2A55",
        And: "\u2A53",
        and: "\u2227",
        andd: "\u2A5C",
        andslope: "\u2A58",
        andv: "\u2A5A",
        ang: "\u2220",
        ange: "\u29A4",
        angle: "\u2220",
        angmsdaa: "\u29A8",
        angmsdab: "\u29A9",
        angmsdac: "\u29AA",
        angmsdad: "\u29AB",
        angmsdae: "\u29AC",
        angmsdaf: "\u29AD",
        angmsdag: "\u29AE",
        angmsdah: "\u29AF",
        angmsd: "\u2221",
        angrt: "\u221F",
        angrtvb: "\u22BE",
        angrtvbd: "\u299D",
        angsph: "\u2222",
        angst: "\xC5",
        angzarr: "\u237C",
        Aogon: "\u0104",
        aogon: "\u0105",
        Aopf: "\u{1D538}",
        aopf: "\u{1D552}",
        apacir: "\u2A6F",
        ap: "\u2248",
        apE: "\u2A70",
        ape: "\u224A",
        apid: "\u224B",
        apos: "'",
        ApplyFunction: "\u2061",
        approx: "\u2248",
        approxeq: "\u224A",
        Aring: "\xC5",
        aring: "\xE5",
        Ascr: "\u{1D49C}",
        ascr: "\u{1D4B6}",
        Assign: "\u2254",
        ast: "*",
        asymp: "\u2248",
        asympeq: "\u224D",
        Atilde: "\xC3",
        atilde: "\xE3",
        Auml: "\xC4",
        auml: "\xE4",
        awconint: "\u2233",
        awint: "\u2A11",
        backcong: "\u224C",
        backepsilon: "\u03F6",
        backprime: "\u2035",
        backsim: "\u223D",
        backsimeq: "\u22CD",
        Backslash: "\u2216",
        Barv: "\u2AE7",
        barvee: "\u22BD",
        barwed: "\u2305",
        Barwed: "\u2306",
        barwedge: "\u2305",
        bbrk: "\u23B5",
        bbrktbrk: "\u23B6",
        bcong: "\u224C",
        Bcy: "\u0411",
        bcy: "\u0431",
        bdquo: "\u201E",
        becaus: "\u2235",
        because: "\u2235",
        Because: "\u2235",
        bemptyv: "\u29B0",
        bepsi: "\u03F6",
        bernou: "\u212C",
        Bernoullis: "\u212C",
        Beta: "\u0392",
        beta: "\u03B2",
        beth: "\u2136",
        between: "\u226C",
        Bfr: "\u{1D505}",
        bfr: "\u{1D51F}",
        bigcap: "\u22C2",
        bigcirc: "\u25EF",
        bigcup: "\u22C3",
        bigodot: "\u2A00",
        bigoplus: "\u2A01",
        bigotimes: "\u2A02",
        bigsqcup: "\u2A06",
        bigstar: "\u2605",
        bigtriangledown: "\u25BD",
        bigtriangleup: "\u25B3",
        biguplus: "\u2A04",
        bigvee: "\u22C1",
        bigwedge: "\u22C0",
        bkarow: "\u290D",
        blacklozenge: "\u29EB",
        blacksquare: "\u25AA",
        blacktriangle: "\u25B4",
        blacktriangledown: "\u25BE",
        blacktriangleleft: "\u25C2",
        blacktriangleright: "\u25B8",
        blank: "\u2423",
        blk12: "\u2592",
        blk14: "\u2591",
        blk34: "\u2593",
        block: "\u2588",
        bne: "=\u20E5",
        bnequiv: "\u2261\u20E5",
        bNot: "\u2AED",
        bnot: "\u2310",
        Bopf: "\u{1D539}",
        bopf: "\u{1D553}",
        bot: "\u22A5",
        bottom: "\u22A5",
        bowtie: "\u22C8",
        boxbox: "\u29C9",
        boxdl: "\u2510",
        boxdL: "\u2555",
        boxDl: "\u2556",
        boxDL: "\u2557",
        boxdr: "\u250C",
        boxdR: "\u2552",
        boxDr: "\u2553",
        boxDR: "\u2554",
        boxh: "\u2500",
        boxH: "\u2550",
        boxhd: "\u252C",
        boxHd: "\u2564",
        boxhD: "\u2565",
        boxHD: "\u2566",
        boxhu: "\u2534",
        boxHu: "\u2567",
        boxhU: "\u2568",
        boxHU: "\u2569",
        boxminus: "\u229F",
        boxplus: "\u229E",
        boxtimes: "\u22A0",
        boxul: "\u2518",
        boxuL: "\u255B",
        boxUl: "\u255C",
        boxUL: "\u255D",
        boxur: "\u2514",
        boxuR: "\u2558",
        boxUr: "\u2559",
        boxUR: "\u255A",
        boxv: "\u2502",
        boxV: "\u2551",
        boxvh: "\u253C",
        boxvH: "\u256A",
        boxVh: "\u256B",
        boxVH: "\u256C",
        boxvl: "\u2524",
        boxvL: "\u2561",
        boxVl: "\u2562",
        boxVL: "\u2563",
        boxvr: "\u251C",
        boxvR: "\u255E",
        boxVr: "\u255F",
        boxVR: "\u2560",
        bprime: "\u2035",
        breve: "\u02D8",
        Breve: "\u02D8",
        brvbar: "\xA6",
        bscr: "\u{1D4B7}",
        Bscr: "\u212C",
        bsemi: "\u204F",
        bsim: "\u223D",
        bsime: "\u22CD",
        bsolb: "\u29C5",
        bsol: "\\",
        bsolhsub: "\u27C8",
        bull: "\u2022",
        bullet: "\u2022",
        bump: "\u224E",
        bumpE: "\u2AAE",
        bumpe: "\u224F",
        Bumpeq: "\u224E",
        bumpeq: "\u224F",
        Cacute: "\u0106",
        cacute: "\u0107",
        capand: "\u2A44",
        capbrcup: "\u2A49",
        capcap: "\u2A4B",
        cap: "\u2229",
        Cap: "\u22D2",
        capcup: "\u2A47",
        capdot: "\u2A40",
        CapitalDifferentialD: "\u2145",
        caps: "\u2229\uFE00",
        caret: "\u2041",
        caron: "\u02C7",
        Cayleys: "\u212D",
        ccaps: "\u2A4D",
        Ccaron: "\u010C",
        ccaron: "\u010D",
        Ccedil: "\xC7",
        ccedil: "\xE7",
        Ccirc: "\u0108",
        ccirc: "\u0109",
        Cconint: "\u2230",
        ccups: "\u2A4C",
        ccupssm: "\u2A50",
        Cdot: "\u010A",
        cdot: "\u010B",
        cedil: "\xB8",
        Cedilla: "\xB8",
        cemptyv: "\u29B2",
        cent: "\xA2",
        centerdot: "\xB7",
        CenterDot: "\xB7",
        cfr: "\u{1D520}",
        Cfr: "\u212D",
        CHcy: "\u0427",
        chcy: "\u0447",
        check: "\u2713",
        checkmark: "\u2713",
        Chi: "\u03A7",
        chi: "\u03C7",
        circ: "\u02C6",
        circeq: "\u2257",
        circlearrowleft: "\u21BA",
        circlearrowright: "\u21BB",
        circledast: "\u229B",
        circledcirc: "\u229A",
        circleddash: "\u229D",
        CircleDot: "\u2299",
        circledR: "\xAE",
        circledS: "\u24C8",
        CircleMinus: "\u2296",
        CirclePlus: "\u2295",
        CircleTimes: "\u2297",
        cir: "\u25CB",
        cirE: "\u29C3",
        cire: "\u2257",
        cirfnint: "\u2A10",
        cirmid: "\u2AEF",
        cirscir: "\u29C2",
        ClockwiseContourIntegral: "\u2232",
        CloseCurlyDoubleQuote: "\u201D",
        CloseCurlyQuote: "\u2019",
        clubs: "\u2663",
        clubsuit: "\u2663",
        colon: ":",
        Colon: "\u2237",
        Colone: "\u2A74",
        colone: "\u2254",
        coloneq: "\u2254",
        comma: ",",
        commat: "@",
        comp: "\u2201",
        compfn: "\u2218",
        complement: "\u2201",
        complexes: "\u2102",
        cong: "\u2245",
        congdot: "\u2A6D",
        Congruent: "\u2261",
        conint: "\u222E",
        Conint: "\u222F",
        ContourIntegral: "\u222E",
        copf: "\u{1D554}",
        Copf: "\u2102",
        coprod: "\u2210",
        Coproduct: "\u2210",
        copy: "\xA9",
        COPY: "\xA9",
        copysr: "\u2117",
        CounterClockwiseContourIntegral: "\u2233",
        crarr: "\u21B5",
        cross: "\u2717",
        Cross: "\u2A2F",
        Cscr: "\u{1D49E}",
        cscr: "\u{1D4B8}",
        csub: "\u2ACF",
        csube: "\u2AD1",
        csup: "\u2AD0",
        csupe: "\u2AD2",
        ctdot: "\u22EF",
        cudarrl: "\u2938",
        cudarrr: "\u2935",
        cuepr: "\u22DE",
        cuesc: "\u22DF",
        cularr: "\u21B6",
        cularrp: "\u293D",
        cupbrcap: "\u2A48",
        cupcap: "\u2A46",
        CupCap: "\u224D",
        cup: "\u222A",
        Cup: "\u22D3",
        cupcup: "\u2A4A",
        cupdot: "\u228D",
        cupor: "\u2A45",
        cups: "\u222A\uFE00",
        curarr: "\u21B7",
        curarrm: "\u293C",
        curlyeqprec: "\u22DE",
        curlyeqsucc: "\u22DF",
        curlyvee: "\u22CE",
        curlywedge: "\u22CF",
        curren: "\xA4",
        curvearrowleft: "\u21B6",
        curvearrowright: "\u21B7",
        cuvee: "\u22CE",
        cuwed: "\u22CF",
        cwconint: "\u2232",
        cwint: "\u2231",
        cylcty: "\u232D",
        dagger: "\u2020",
        Dagger: "\u2021",
        daleth: "\u2138",
        darr: "\u2193",
        Darr: "\u21A1",
        dArr: "\u21D3",
        dash: "\u2010",
        Dashv: "\u2AE4",
        dashv: "\u22A3",
        dbkarow: "\u290F",
        dblac: "\u02DD",
        Dcaron: "\u010E",
        dcaron: "\u010F",
        Dcy: "\u0414",
        dcy: "\u0434",
        ddagger: "\u2021",
        ddarr: "\u21CA",
        DD: "\u2145",
        dd: "\u2146",
        DDotrahd: "\u2911",
        ddotseq: "\u2A77",
        deg: "\xB0",
        Del: "\u2207",
        Delta: "\u0394",
        delta: "\u03B4",
        demptyv: "\u29B1",
        dfisht: "\u297F",
        Dfr: "\u{1D507}",
        dfr: "\u{1D521}",
        dHar: "\u2965",
        dharl: "\u21C3",
        dharr: "\u21C2",
        DiacriticalAcute: "\xB4",
        DiacriticalDot: "\u02D9",
        DiacriticalDoubleAcute: "\u02DD",
        DiacriticalGrave: "`",
        DiacriticalTilde: "\u02DC",
        diam: "\u22C4",
        diamond: "\u22C4",
        Diamond: "\u22C4",
        diamondsuit: "\u2666",
        diams: "\u2666",
        die: "\xA8",
        DifferentialD: "\u2146",
        digamma: "\u03DD",
        disin: "\u22F2",
        div: "\xF7",
        divide: "\xF7",
        divideontimes: "\u22C7",
        divonx: "\u22C7",
        DJcy: "\u0402",
        djcy: "\u0452",
        dlcorn: "\u231E",
        dlcrop: "\u230D",
        dollar: "$",
        Dopf: "\u{1D53B}",
        dopf: "\u{1D555}",
        Dot: "\xA8",
        dot: "\u02D9",
        DotDot: "\u20DC",
        doteq: "\u2250",
        doteqdot: "\u2251",
        DotEqual: "\u2250",
        dotminus: "\u2238",
        dotplus: "\u2214",
        dotsquare: "\u22A1",
        doublebarwedge: "\u2306",
        DoubleContourIntegral: "\u222F",
        DoubleDot: "\xA8",
        DoubleDownArrow: "\u21D3",
        DoubleLeftArrow: "\u21D0",
        DoubleLeftRightArrow: "\u21D4",
        DoubleLeftTee: "\u2AE4",
        DoubleLongLeftArrow: "\u27F8",
        DoubleLongLeftRightArrow: "\u27FA",
        DoubleLongRightArrow: "\u27F9",
        DoubleRightArrow: "\u21D2",
        DoubleRightTee: "\u22A8",
        DoubleUpArrow: "\u21D1",
        DoubleUpDownArrow: "\u21D5",
        DoubleVerticalBar: "\u2225",
        DownArrowBar: "\u2913",
        downarrow: "\u2193",
        DownArrow: "\u2193",
        Downarrow: "\u21D3",
        DownArrowUpArrow: "\u21F5",
        DownBreve: "\u0311",
        downdownarrows: "\u21CA",
        downharpoonleft: "\u21C3",
        downharpoonright: "\u21C2",
        DownLeftRightVector: "\u2950",
        DownLeftTeeVector: "\u295E",
        DownLeftVectorBar: "\u2956",
        DownLeftVector: "\u21BD",
        DownRightTeeVector: "\u295F",
        DownRightVectorBar: "\u2957",
        DownRightVector: "\u21C1",
        DownTeeArrow: "\u21A7",
        DownTee: "\u22A4",
        drbkarow: "\u2910",
        drcorn: "\u231F",
        drcrop: "\u230C",
        Dscr: "\u{1D49F}",
        dscr: "\u{1D4B9}",
        DScy: "\u0405",
        dscy: "\u0455",
        dsol: "\u29F6",
        Dstrok: "\u0110",
        dstrok: "\u0111",
        dtdot: "\u22F1",
        dtri: "\u25BF",
        dtrif: "\u25BE",
        duarr: "\u21F5",
        duhar: "\u296F",
        dwangle: "\u29A6",
        DZcy: "\u040F",
        dzcy: "\u045F",
        dzigrarr: "\u27FF",
        Eacute: "\xC9",
        eacute: "\xE9",
        easter: "\u2A6E",
        Ecaron: "\u011A",
        ecaron: "\u011B",
        Ecirc: "\xCA",
        ecirc: "\xEA",
        ecir: "\u2256",
        ecolon: "\u2255",
        Ecy: "\u042D",
        ecy: "\u044D",
        eDDot: "\u2A77",
        Edot: "\u0116",
        edot: "\u0117",
        eDot: "\u2251",
        ee: "\u2147",
        efDot: "\u2252",
        Efr: "\u{1D508}",
        efr: "\u{1D522}",
        eg: "\u2A9A",
        Egrave: "\xC8",
        egrave: "\xE8",
        egs: "\u2A96",
        egsdot: "\u2A98",
        el: "\u2A99",
        Element: "\u2208",
        elinters: "\u23E7",
        ell: "\u2113",
        els: "\u2A95",
        elsdot: "\u2A97",
        Emacr: "\u0112",
        emacr: "\u0113",
        empty: "\u2205",
        emptyset: "\u2205",
        EmptySmallSquare: "\u25FB",
        emptyv: "\u2205",
        EmptyVerySmallSquare: "\u25AB",
        emsp13: "\u2004",
        emsp14: "\u2005",
        emsp: "\u2003",
        ENG: "\u014A",
        eng: "\u014B",
        ensp: "\u2002",
        Eogon: "\u0118",
        eogon: "\u0119",
        Eopf: "\u{1D53C}",
        eopf: "\u{1D556}",
        epar: "\u22D5",
        eparsl: "\u29E3",
        eplus: "\u2A71",
        epsi: "\u03B5",
        Epsilon: "\u0395",
        epsilon: "\u03B5",
        epsiv: "\u03F5",
        eqcirc: "\u2256",
        eqcolon: "\u2255",
        eqsim: "\u2242",
        eqslantgtr: "\u2A96",
        eqslantless: "\u2A95",
        Equal: "\u2A75",
        equals: "=",
        EqualTilde: "\u2242",
        equest: "\u225F",
        Equilibrium: "\u21CC",
        equiv: "\u2261",
        equivDD: "\u2A78",
        eqvparsl: "\u29E5",
        erarr: "\u2971",
        erDot: "\u2253",
        escr: "\u212F",
        Escr: "\u2130",
        esdot: "\u2250",
        Esim: "\u2A73",
        esim: "\u2242",
        Eta: "\u0397",
        eta: "\u03B7",
        ETH: "\xD0",
        eth: "\xF0",
        Euml: "\xCB",
        euml: "\xEB",
        euro: "\u20AC",
        excl: "!",
        exist: "\u2203",
        Exists: "\u2203",
        expectation: "\u2130",
        exponentiale: "\u2147",
        ExponentialE: "\u2147",
        fallingdotseq: "\u2252",
        Fcy: "\u0424",
        fcy: "\u0444",
        female: "\u2640",
        ffilig: "\uFB03",
        fflig: "\uFB00",
        ffllig: "\uFB04",
        Ffr: "\u{1D509}",
        ffr: "\u{1D523}",
        filig: "\uFB01",
        FilledSmallSquare: "\u25FC",
        FilledVerySmallSquare: "\u25AA",
        fjlig: "fj",
        flat: "\u266D",
        fllig: "\uFB02",
        fltns: "\u25B1",
        fnof: "\u0192",
        Fopf: "\u{1D53D}",
        fopf: "\u{1D557}",
        forall: "\u2200",
        ForAll: "\u2200",
        fork: "\u22D4",
        forkv: "\u2AD9",
        Fouriertrf: "\u2131",
        fpartint: "\u2A0D",
        frac12: "\xBD",
        frac13: "\u2153",
        frac14: "\xBC",
        frac15: "\u2155",
        frac16: "\u2159",
        frac18: "\u215B",
        frac23: "\u2154",
        frac25: "\u2156",
        frac34: "\xBE",
        frac35: "\u2157",
        frac38: "\u215C",
        frac45: "\u2158",
        frac56: "\u215A",
        frac58: "\u215D",
        frac78: "\u215E",
        frasl: "\u2044",
        frown: "\u2322",
        fscr: "\u{1D4BB}",
        Fscr: "\u2131",
        gacute: "\u01F5",
        Gamma: "\u0393",
        gamma: "\u03B3",
        Gammad: "\u03DC",
        gammad: "\u03DD",
        gap: "\u2A86",
        Gbreve: "\u011E",
        gbreve: "\u011F",
        Gcedil: "\u0122",
        Gcirc: "\u011C",
        gcirc: "\u011D",
        Gcy: "\u0413",
        gcy: "\u0433",
        Gdot: "\u0120",
        gdot: "\u0121",
        ge: "\u2265",
        gE: "\u2267",
        gEl: "\u2A8C",
        gel: "\u22DB",
        geq: "\u2265",
        geqq: "\u2267",
        geqslant: "\u2A7E",
        gescc: "\u2AA9",
        ges: "\u2A7E",
        gesdot: "\u2A80",
        gesdoto: "\u2A82",
        gesdotol: "\u2A84",
        gesl: "\u22DB\uFE00",
        gesles: "\u2A94",
        Gfr: "\u{1D50A}",
        gfr: "\u{1D524}",
        gg: "\u226B",
        Gg: "\u22D9",
        ggg: "\u22D9",
        gimel: "\u2137",
        GJcy: "\u0403",
        gjcy: "\u0453",
        gla: "\u2AA5",
        gl: "\u2277",
        glE: "\u2A92",
        glj: "\u2AA4",
        gnap: "\u2A8A",
        gnapprox: "\u2A8A",
        gne: "\u2A88",
        gnE: "\u2269",
        gneq: "\u2A88",
        gneqq: "\u2269",
        gnsim: "\u22E7",
        Gopf: "\u{1D53E}",
        gopf: "\u{1D558}",
        grave: "`",
        GreaterEqual: "\u2265",
        GreaterEqualLess: "\u22DB",
        GreaterFullEqual: "\u2267",
        GreaterGreater: "\u2AA2",
        GreaterLess: "\u2277",
        GreaterSlantEqual: "\u2A7E",
        GreaterTilde: "\u2273",
        Gscr: "\u{1D4A2}",
        gscr: "\u210A",
        gsim: "\u2273",
        gsime: "\u2A8E",
        gsiml: "\u2A90",
        gtcc: "\u2AA7",
        gtcir: "\u2A7A",
        gt: ">",
        GT: ">",
        Gt: "\u226B",
        gtdot: "\u22D7",
        gtlPar: "\u2995",
        gtquest: "\u2A7C",
        gtrapprox: "\u2A86",
        gtrarr: "\u2978",
        gtrdot: "\u22D7",
        gtreqless: "\u22DB",
        gtreqqless: "\u2A8C",
        gtrless: "\u2277",
        gtrsim: "\u2273",
        gvertneqq: "\u2269\uFE00",
        gvnE: "\u2269\uFE00",
        Hacek: "\u02C7",
        hairsp: "\u200A",
        half: "\xBD",
        hamilt: "\u210B",
        HARDcy: "\u042A",
        hardcy: "\u044A",
        harrcir: "\u2948",
        harr: "\u2194",
        hArr: "\u21D4",
        harrw: "\u21AD",
        Hat: "^",
        hbar: "\u210F",
        Hcirc: "\u0124",
        hcirc: "\u0125",
        hearts: "\u2665",
        heartsuit: "\u2665",
        hellip: "\u2026",
        hercon: "\u22B9",
        hfr: "\u{1D525}",
        Hfr: "\u210C",
        HilbertSpace: "\u210B",
        hksearow: "\u2925",
        hkswarow: "\u2926",
        hoarr: "\u21FF",
        homtht: "\u223B",
        hookleftarrow: "\u21A9",
        hookrightarrow: "\u21AA",
        hopf: "\u{1D559}",
        Hopf: "\u210D",
        horbar: "\u2015",
        HorizontalLine: "\u2500",
        hscr: "\u{1D4BD}",
        Hscr: "\u210B",
        hslash: "\u210F",
        Hstrok: "\u0126",
        hstrok: "\u0127",
        HumpDownHump: "\u224E",
        HumpEqual: "\u224F",
        hybull: "\u2043",
        hyphen: "\u2010",
        Iacute: "\xCD",
        iacute: "\xED",
        ic: "\u2063",
        Icirc: "\xCE",
        icirc: "\xEE",
        Icy: "\u0418",
        icy: "\u0438",
        Idot: "\u0130",
        IEcy: "\u0415",
        iecy: "\u0435",
        iexcl: "\xA1",
        iff: "\u21D4",
        ifr: "\u{1D526}",
        Ifr: "\u2111",
        Igrave: "\xCC",
        igrave: "\xEC",
        ii: "\u2148",
        iiiint: "\u2A0C",
        iiint: "\u222D",
        iinfin: "\u29DC",
        iiota: "\u2129",
        IJlig: "\u0132",
        ijlig: "\u0133",
        Imacr: "\u012A",
        imacr: "\u012B",
        image: "\u2111",
        ImaginaryI: "\u2148",
        imagline: "\u2110",
        imagpart: "\u2111",
        imath: "\u0131",
        Im: "\u2111",
        imof: "\u22B7",
        imped: "\u01B5",
        Implies: "\u21D2",
        incare: "\u2105",
        in: "\u2208",
        infin: "\u221E",
        infintie: "\u29DD",
        inodot: "\u0131",
        intcal: "\u22BA",
        int: "\u222B",
        Int: "\u222C",
        integers: "\u2124",
        Integral: "\u222B",
        intercal: "\u22BA",
        Intersection: "\u22C2",
        intlarhk: "\u2A17",
        intprod: "\u2A3C",
        InvisibleComma: "\u2063",
        InvisibleTimes: "\u2062",
        IOcy: "\u0401",
        iocy: "\u0451",
        Iogon: "\u012E",
        iogon: "\u012F",
        Iopf: "\u{1D540}",
        iopf: "\u{1D55A}",
        Iota: "\u0399",
        iota: "\u03B9",
        iprod: "\u2A3C",
        iquest: "\xBF",
        iscr: "\u{1D4BE}",
        Iscr: "\u2110",
        isin: "\u2208",
        isindot: "\u22F5",
        isinE: "\u22F9",
        isins: "\u22F4",
        isinsv: "\u22F3",
        isinv: "\u2208",
        it: "\u2062",
        Itilde: "\u0128",
        itilde: "\u0129",
        Iukcy: "\u0406",
        iukcy: "\u0456",
        Iuml: "\xCF",
        iuml: "\xEF",
        Jcirc: "\u0134",
        jcirc: "\u0135",
        Jcy: "\u0419",
        jcy: "\u0439",
        Jfr: "\u{1D50D}",
        jfr: "\u{1D527}",
        jmath: "\u0237",
        Jopf: "\u{1D541}",
        jopf: "\u{1D55B}",
        Jscr: "\u{1D4A5}",
        jscr: "\u{1D4BF}",
        Jsercy: "\u0408",
        jsercy: "\u0458",
        Jukcy: "\u0404",
        jukcy: "\u0454",
        Kappa: "\u039A",
        kappa: "\u03BA",
        kappav: "\u03F0",
        Kcedil: "\u0136",
        kcedil: "\u0137",
        Kcy: "\u041A",
        kcy: "\u043A",
        Kfr: "\u{1D50E}",
        kfr: "\u{1D528}",
        kgreen: "\u0138",
        KHcy: "\u0425",
        khcy: "\u0445",
        KJcy: "\u040C",
        kjcy: "\u045C",
        Kopf: "\u{1D542}",
        kopf: "\u{1D55C}",
        Kscr: "\u{1D4A6}",
        kscr: "\u{1D4C0}",
        lAarr: "\u21DA",
        Lacute: "\u0139",
        lacute: "\u013A",
        laemptyv: "\u29B4",
        lagran: "\u2112",
        Lambda: "\u039B",
        lambda: "\u03BB",
        lang: "\u27E8",
        Lang: "\u27EA",
        langd: "\u2991",
        langle: "\u27E8",
        lap: "\u2A85",
        Laplacetrf: "\u2112",
        laquo: "\xAB",
        larrb: "\u21E4",
        larrbfs: "\u291F",
        larr: "\u2190",
        Larr: "\u219E",
        lArr: "\u21D0",
        larrfs: "\u291D",
        larrhk: "\u21A9",
        larrlp: "\u21AB",
        larrpl: "\u2939",
        larrsim: "\u2973",
        larrtl: "\u21A2",
        latail: "\u2919",
        lAtail: "\u291B",
        lat: "\u2AAB",
        late: "\u2AAD",
        lates: "\u2AAD\uFE00",
        lbarr: "\u290C",
        lBarr: "\u290E",
        lbbrk: "\u2772",
        lbrace: "{",
        lbrack: "[",
        lbrke: "\u298B",
        lbrksld: "\u298F",
        lbrkslu: "\u298D",
        Lcaron: "\u013D",
        lcaron: "\u013E",
        Lcedil: "\u013B",
        lcedil: "\u013C",
        lceil: "\u2308",
        lcub: "{",
        Lcy: "\u041B",
        lcy: "\u043B",
        ldca: "\u2936",
        ldquo: "\u201C",
        ldquor: "\u201E",
        ldrdhar: "\u2967",
        ldrushar: "\u294B",
        ldsh: "\u21B2",
        le: "\u2264",
        lE: "\u2266",
        LeftAngleBracket: "\u27E8",
        LeftArrowBar: "\u21E4",
        leftarrow: "\u2190",
        LeftArrow: "\u2190",
        Leftarrow: "\u21D0",
        LeftArrowRightArrow: "\u21C6",
        leftarrowtail: "\u21A2",
        LeftCeiling: "\u2308",
        LeftDoubleBracket: "\u27E6",
        LeftDownTeeVector: "\u2961",
        LeftDownVectorBar: "\u2959",
        LeftDownVector: "\u21C3",
        LeftFloor: "\u230A",
        leftharpoondown: "\u21BD",
        leftharpoonup: "\u21BC",
        leftleftarrows: "\u21C7",
        leftrightarrow: "\u2194",
        LeftRightArrow: "\u2194",
        Leftrightarrow: "\u21D4",
        leftrightarrows: "\u21C6",
        leftrightharpoons: "\u21CB",
        leftrightsquigarrow: "\u21AD",
        LeftRightVector: "\u294E",
        LeftTeeArrow: "\u21A4",
        LeftTee: "\u22A3",
        LeftTeeVector: "\u295A",
        leftthreetimes: "\u22CB",
        LeftTriangleBar: "\u29CF",
        LeftTriangle: "\u22B2",
        LeftTriangleEqual: "\u22B4",
        LeftUpDownVector: "\u2951",
        LeftUpTeeVector: "\u2960",
        LeftUpVectorBar: "\u2958",
        LeftUpVector: "\u21BF",
        LeftVectorBar: "\u2952",
        LeftVector: "\u21BC",
        lEg: "\u2A8B",
        leg: "\u22DA",
        leq: "\u2264",
        leqq: "\u2266",
        leqslant: "\u2A7D",
        lescc: "\u2AA8",
        les: "\u2A7D",
        lesdot: "\u2A7F",
        lesdoto: "\u2A81",
        lesdotor: "\u2A83",
        lesg: "\u22DA\uFE00",
        lesges: "\u2A93",
        lessapprox: "\u2A85",
        lessdot: "\u22D6",
        lesseqgtr: "\u22DA",
        lesseqqgtr: "\u2A8B",
        LessEqualGreater: "\u22DA",
        LessFullEqual: "\u2266",
        LessGreater: "\u2276",
        lessgtr: "\u2276",
        LessLess: "\u2AA1",
        lesssim: "\u2272",
        LessSlantEqual: "\u2A7D",
        LessTilde: "\u2272",
        lfisht: "\u297C",
        lfloor: "\u230A",
        Lfr: "\u{1D50F}",
        lfr: "\u{1D529}",
        lg: "\u2276",
        lgE: "\u2A91",
        lHar: "\u2962",
        lhard: "\u21BD",
        lharu: "\u21BC",
        lharul: "\u296A",
        lhblk: "\u2584",
        LJcy: "\u0409",
        ljcy: "\u0459",
        llarr: "\u21C7",
        ll: "\u226A",
        Ll: "\u22D8",
        llcorner: "\u231E",
        Lleftarrow: "\u21DA",
        llhard: "\u296B",
        lltri: "\u25FA",
        Lmidot: "\u013F",
        lmidot: "\u0140",
        lmoustache: "\u23B0",
        lmoust: "\u23B0",
        lnap: "\u2A89",
        lnapprox: "\u2A89",
        lne: "\u2A87",
        lnE: "\u2268",
        lneq: "\u2A87",
        lneqq: "\u2268",
        lnsim: "\u22E6",
        loang: "\u27EC",
        loarr: "\u21FD",
        lobrk: "\u27E6",
        longleftarrow: "\u27F5",
        LongLeftArrow: "\u27F5",
        Longleftarrow: "\u27F8",
        longleftrightarrow: "\u27F7",
        LongLeftRightArrow: "\u27F7",
        Longleftrightarrow: "\u27FA",
        longmapsto: "\u27FC",
        longrightarrow: "\u27F6",
        LongRightArrow: "\u27F6",
        Longrightarrow: "\u27F9",
        looparrowleft: "\u21AB",
        looparrowright: "\u21AC",
        lopar: "\u2985",
        Lopf: "\u{1D543}",
        lopf: "\u{1D55D}",
        loplus: "\u2A2D",
        lotimes: "\u2A34",
        lowast: "\u2217",
        lowbar: "_",
        LowerLeftArrow: "\u2199",
        LowerRightArrow: "\u2198",
        loz: "\u25CA",
        lozenge: "\u25CA",
        lozf: "\u29EB",
        lpar: "(",
        lparlt: "\u2993",
        lrarr: "\u21C6",
        lrcorner: "\u231F",
        lrhar: "\u21CB",
        lrhard: "\u296D",
        lrm: "\u200E",
        lrtri: "\u22BF",
        lsaquo: "\u2039",
        lscr: "\u{1D4C1}",
        Lscr: "\u2112",
        lsh: "\u21B0",
        Lsh: "\u21B0",
        lsim: "\u2272",
        lsime: "\u2A8D",
        lsimg: "\u2A8F",
        lsqb: "[",
        lsquo: "\u2018",
        lsquor: "\u201A",
        Lstrok: "\u0141",
        lstrok: "\u0142",
        ltcc: "\u2AA6",
        ltcir: "\u2A79",
        lt: "<",
        LT: "<",
        Lt: "\u226A",
        ltdot: "\u22D6",
        lthree: "\u22CB",
        ltimes: "\u22C9",
        ltlarr: "\u2976",
        ltquest: "\u2A7B",
        ltri: "\u25C3",
        ltrie: "\u22B4",
        ltrif: "\u25C2",
        ltrPar: "\u2996",
        lurdshar: "\u294A",
        luruhar: "\u2966",
        lvertneqq: "\u2268\uFE00",
        lvnE: "\u2268\uFE00",
        macr: "\xAF",
        male: "\u2642",
        malt: "\u2720",
        maltese: "\u2720",
        Map: "\u2905",
        map: "\u21A6",
        mapsto: "\u21A6",
        mapstodown: "\u21A7",
        mapstoleft: "\u21A4",
        mapstoup: "\u21A5",
        marker: "\u25AE",
        mcomma: "\u2A29",
        Mcy: "\u041C",
        mcy: "\u043C",
        mdash: "\u2014",
        mDDot: "\u223A",
        measuredangle: "\u2221",
        MediumSpace: "\u205F",
        Mellintrf: "\u2133",
        Mfr: "\u{1D510}",
        mfr: "\u{1D52A}",
        mho: "\u2127",
        micro: "\xB5",
        midast: "*",
        midcir: "\u2AF0",
        mid: "\u2223",
        middot: "\xB7",
        minusb: "\u229F",
        minus: "\u2212",
        minusd: "\u2238",
        minusdu: "\u2A2A",
        MinusPlus: "\u2213",
        mlcp: "\u2ADB",
        mldr: "\u2026",
        mnplus: "\u2213",
        models: "\u22A7",
        Mopf: "\u{1D544}",
        mopf: "\u{1D55E}",
        mp: "\u2213",
        mscr: "\u{1D4C2}",
        Mscr: "\u2133",
        mstpos: "\u223E",
        Mu: "\u039C",
        mu: "\u03BC",
        multimap: "\u22B8",
        mumap: "\u22B8",
        nabla: "\u2207",
        Nacute: "\u0143",
        nacute: "\u0144",
        nang: "\u2220\u20D2",
        nap: "\u2249",
        napE: "\u2A70\u0338",
        napid: "\u224B\u0338",
        napos: "\u0149",
        napprox: "\u2249",
        natural: "\u266E",
        naturals: "\u2115",
        natur: "\u266E",
        nbsp: "\xA0",
        nbump: "\u224E\u0338",
        nbumpe: "\u224F\u0338",
        ncap: "\u2A43",
        Ncaron: "\u0147",
        ncaron: "\u0148",
        Ncedil: "\u0145",
        ncedil: "\u0146",
        ncong: "\u2247",
        ncongdot: "\u2A6D\u0338",
        ncup: "\u2A42",
        Ncy: "\u041D",
        ncy: "\u043D",
        ndash: "\u2013",
        nearhk: "\u2924",
        nearr: "\u2197",
        neArr: "\u21D7",
        nearrow: "\u2197",
        ne: "\u2260",
        nedot: "\u2250\u0338",
        NegativeMediumSpace: "\u200B",
        NegativeThickSpace: "\u200B",
        NegativeThinSpace: "\u200B",
        NegativeVeryThinSpace: "\u200B",
        nequiv: "\u2262",
        nesear: "\u2928",
        nesim: "\u2242\u0338",
        NestedGreaterGreater: "\u226B",
        NestedLessLess: "\u226A",
        NewLine: `
`,
        nexist: "\u2204",
        nexists: "\u2204",
        Nfr: "\u{1D511}",
        nfr: "\u{1D52B}",
        ngE: "\u2267\u0338",
        nge: "\u2271",
        ngeq: "\u2271",
        ngeqq: "\u2267\u0338",
        ngeqslant: "\u2A7E\u0338",
        nges: "\u2A7E\u0338",
        nGg: "\u22D9\u0338",
        ngsim: "\u2275",
        nGt: "\u226B\u20D2",
        ngt: "\u226F",
        ngtr: "\u226F",
        nGtv: "\u226B\u0338",
        nharr: "\u21AE",
        nhArr: "\u21CE",
        nhpar: "\u2AF2",
        ni: "\u220B",
        nis: "\u22FC",
        nisd: "\u22FA",
        niv: "\u220B",
        NJcy: "\u040A",
        njcy: "\u045A",
        nlarr: "\u219A",
        nlArr: "\u21CD",
        nldr: "\u2025",
        nlE: "\u2266\u0338",
        nle: "\u2270",
        nleftarrow: "\u219A",
        nLeftarrow: "\u21CD",
        nleftrightarrow: "\u21AE",
        nLeftrightarrow: "\u21CE",
        nleq: "\u2270",
        nleqq: "\u2266\u0338",
        nleqslant: "\u2A7D\u0338",
        nles: "\u2A7D\u0338",
        nless: "\u226E",
        nLl: "\u22D8\u0338",
        nlsim: "\u2274",
        nLt: "\u226A\u20D2",
        nlt: "\u226E",
        nltri: "\u22EA",
        nltrie: "\u22EC",
        nLtv: "\u226A\u0338",
        nmid: "\u2224",
        NoBreak: "\u2060",
        NonBreakingSpace: "\xA0",
        nopf: "\u{1D55F}",
        Nopf: "\u2115",
        Not: "\u2AEC",
        not: "\xAC",
        NotCongruent: "\u2262",
        NotCupCap: "\u226D",
        NotDoubleVerticalBar: "\u2226",
        NotElement: "\u2209",
        NotEqual: "\u2260",
        NotEqualTilde: "\u2242\u0338",
        NotExists: "\u2204",
        NotGreater: "\u226F",
        NotGreaterEqual: "\u2271",
        NotGreaterFullEqual: "\u2267\u0338",
        NotGreaterGreater: "\u226B\u0338",
        NotGreaterLess: "\u2279",
        NotGreaterSlantEqual: "\u2A7E\u0338",
        NotGreaterTilde: "\u2275",
        NotHumpDownHump: "\u224E\u0338",
        NotHumpEqual: "\u224F\u0338",
        notin: "\u2209",
        notindot: "\u22F5\u0338",
        notinE: "\u22F9\u0338",
        notinva: "\u2209",
        notinvb: "\u22F7",
        notinvc: "\u22F6",
        NotLeftTriangleBar: "\u29CF\u0338",
        NotLeftTriangle: "\u22EA",
        NotLeftTriangleEqual: "\u22EC",
        NotLess: "\u226E",
        NotLessEqual: "\u2270",
        NotLessGreater: "\u2278",
        NotLessLess: "\u226A\u0338",
        NotLessSlantEqual: "\u2A7D\u0338",
        NotLessTilde: "\u2274",
        NotNestedGreaterGreater: "\u2AA2\u0338",
        NotNestedLessLess: "\u2AA1\u0338",
        notni: "\u220C",
        notniva: "\u220C",
        notnivb: "\u22FE",
        notnivc: "\u22FD",
        NotPrecedes: "\u2280",
        NotPrecedesEqual: "\u2AAF\u0338",
        NotPrecedesSlantEqual: "\u22E0",
        NotReverseElement: "\u220C",
        NotRightTriangleBar: "\u29D0\u0338",
        NotRightTriangle: "\u22EB",
        NotRightTriangleEqual: "\u22ED",
        NotSquareSubset: "\u228F\u0338",
        NotSquareSubsetEqual: "\u22E2",
        NotSquareSuperset: "\u2290\u0338",
        NotSquareSupersetEqual: "\u22E3",
        NotSubset: "\u2282\u20D2",
        NotSubsetEqual: "\u2288",
        NotSucceeds: "\u2281",
        NotSucceedsEqual: "\u2AB0\u0338",
        NotSucceedsSlantEqual: "\u22E1",
        NotSucceedsTilde: "\u227F\u0338",
        NotSuperset: "\u2283\u20D2",
        NotSupersetEqual: "\u2289",
        NotTilde: "\u2241",
        NotTildeEqual: "\u2244",
        NotTildeFullEqual: "\u2247",
        NotTildeTilde: "\u2249",
        NotVerticalBar: "\u2224",
        nparallel: "\u2226",
        npar: "\u2226",
        nparsl: "\u2AFD\u20E5",
        npart: "\u2202\u0338",
        npolint: "\u2A14",
        npr: "\u2280",
        nprcue: "\u22E0",
        nprec: "\u2280",
        npreceq: "\u2AAF\u0338",
        npre: "\u2AAF\u0338",
        nrarrc: "\u2933\u0338",
        nrarr: "\u219B",
        nrArr: "\u21CF",
        nrarrw: "\u219D\u0338",
        nrightarrow: "\u219B",
        nRightarrow: "\u21CF",
        nrtri: "\u22EB",
        nrtrie: "\u22ED",
        nsc: "\u2281",
        nsccue: "\u22E1",
        nsce: "\u2AB0\u0338",
        Nscr: "\u{1D4A9}",
        nscr: "\u{1D4C3}",
        nshortmid: "\u2224",
        nshortparallel: "\u2226",
        nsim: "\u2241",
        nsime: "\u2244",
        nsimeq: "\u2244",
        nsmid: "\u2224",
        nspar: "\u2226",
        nsqsube: "\u22E2",
        nsqsupe: "\u22E3",
        nsub: "\u2284",
        nsubE: "\u2AC5\u0338",
        nsube: "\u2288",
        nsubset: "\u2282\u20D2",
        nsubseteq: "\u2288",
        nsubseteqq: "\u2AC5\u0338",
        nsucc: "\u2281",
        nsucceq: "\u2AB0\u0338",
        nsup: "\u2285",
        nsupE: "\u2AC6\u0338",
        nsupe: "\u2289",
        nsupset: "\u2283\u20D2",
        nsupseteq: "\u2289",
        nsupseteqq: "\u2AC6\u0338",
        ntgl: "\u2279",
        Ntilde: "\xD1",
        ntilde: "\xF1",
        ntlg: "\u2278",
        ntriangleleft: "\u22EA",
        ntrianglelefteq: "\u22EC",
        ntriangleright: "\u22EB",
        ntrianglerighteq: "\u22ED",
        Nu: "\u039D",
        nu: "\u03BD",
        num: "#",
        numero: "\u2116",
        numsp: "\u2007",
        nvap: "\u224D\u20D2",
        nvdash: "\u22AC",
        nvDash: "\u22AD",
        nVdash: "\u22AE",
        nVDash: "\u22AF",
        nvge: "\u2265\u20D2",
        nvgt: ">\u20D2",
        nvHarr: "\u2904",
        nvinfin: "\u29DE",
        nvlArr: "\u2902",
        nvle: "\u2264\u20D2",
        nvlt: "<\u20D2",
        nvltrie: "\u22B4\u20D2",
        nvrArr: "\u2903",
        nvrtrie: "\u22B5\u20D2",
        nvsim: "\u223C\u20D2",
        nwarhk: "\u2923",
        nwarr: "\u2196",
        nwArr: "\u21D6",
        nwarrow: "\u2196",
        nwnear: "\u2927",
        Oacute: "\xD3",
        oacute: "\xF3",
        oast: "\u229B",
        Ocirc: "\xD4",
        ocirc: "\xF4",
        ocir: "\u229A",
        Ocy: "\u041E",
        ocy: "\u043E",
        odash: "\u229D",
        Odblac: "\u0150",
        odblac: "\u0151",
        odiv: "\u2A38",
        odot: "\u2299",
        odsold: "\u29BC",
        OElig: "\u0152",
        oelig: "\u0153",
        ofcir: "\u29BF",
        Ofr: "\u{1D512}",
        ofr: "\u{1D52C}",
        ogon: "\u02DB",
        Ograve: "\xD2",
        ograve: "\xF2",
        ogt: "\u29C1",
        ohbar: "\u29B5",
        ohm: "\u03A9",
        oint: "\u222E",
        olarr: "\u21BA",
        olcir: "\u29BE",
        olcross: "\u29BB",
        oline: "\u203E",
        olt: "\u29C0",
        Omacr: "\u014C",
        omacr: "\u014D",
        Omega: "\u03A9",
        omega: "\u03C9",
        Omicron: "\u039F",
        omicron: "\u03BF",
        omid: "\u29B6",
        ominus: "\u2296",
        Oopf: "\u{1D546}",
        oopf: "\u{1D560}",
        opar: "\u29B7",
        OpenCurlyDoubleQuote: "\u201C",
        OpenCurlyQuote: "\u2018",
        operp: "\u29B9",
        oplus: "\u2295",
        orarr: "\u21BB",
        Or: "\u2A54",
        or: "\u2228",
        ord: "\u2A5D",
        order: "\u2134",
        orderof: "\u2134",
        ordf: "\xAA",
        ordm: "\xBA",
        origof: "\u22B6",
        oror: "\u2A56",
        orslope: "\u2A57",
        orv: "\u2A5B",
        oS: "\u24C8",
        Oscr: "\u{1D4AA}",
        oscr: "\u2134",
        Oslash: "\xD8",
        oslash: "\xF8",
        osol: "\u2298",
        Otilde: "\xD5",
        otilde: "\xF5",
        otimesas: "\u2A36",
        Otimes: "\u2A37",
        otimes: "\u2297",
        Ouml: "\xD6",
        ouml: "\xF6",
        ovbar: "\u233D",
        OverBar: "\u203E",
        OverBrace: "\u23DE",
        OverBracket: "\u23B4",
        OverParenthesis: "\u23DC",
        para: "\xB6",
        parallel: "\u2225",
        par: "\u2225",
        parsim: "\u2AF3",
        parsl: "\u2AFD",
        part: "\u2202",
        PartialD: "\u2202",
        Pcy: "\u041F",
        pcy: "\u043F",
        percnt: "%",
        period: ".",
        permil: "\u2030",
        perp: "\u22A5",
        pertenk: "\u2031",
        Pfr: "\u{1D513}",
        pfr: "\u{1D52D}",
        Phi: "\u03A6",
        phi: "\u03C6",
        phiv: "\u03D5",
        phmmat: "\u2133",
        phone: "\u260E",
        Pi: "\u03A0",
        pi: "\u03C0",
        pitchfork: "\u22D4",
        piv: "\u03D6",
        planck: "\u210F",
        planckh: "\u210E",
        plankv: "\u210F",
        plusacir: "\u2A23",
        plusb: "\u229E",
        pluscir: "\u2A22",
        plus: "+",
        plusdo: "\u2214",
        plusdu: "\u2A25",
        pluse: "\u2A72",
        PlusMinus: "\xB1",
        plusmn: "\xB1",
        plussim: "\u2A26",
        plustwo: "\u2A27",
        pm: "\xB1",
        Poincareplane: "\u210C",
        pointint: "\u2A15",
        popf: "\u{1D561}",
        Popf: "\u2119",
        pound: "\xA3",
        prap: "\u2AB7",
        Pr: "\u2ABB",
        pr: "\u227A",
        prcue: "\u227C",
        precapprox: "\u2AB7",
        prec: "\u227A",
        preccurlyeq: "\u227C",
        Precedes: "\u227A",
        PrecedesEqual: "\u2AAF",
        PrecedesSlantEqual: "\u227C",
        PrecedesTilde: "\u227E",
        preceq: "\u2AAF",
        precnapprox: "\u2AB9",
        precneqq: "\u2AB5",
        precnsim: "\u22E8",
        pre: "\u2AAF",
        prE: "\u2AB3",
        precsim: "\u227E",
        prime: "\u2032",
        Prime: "\u2033",
        primes: "\u2119",
        prnap: "\u2AB9",
        prnE: "\u2AB5",
        prnsim: "\u22E8",
        prod: "\u220F",
        Product: "\u220F",
        profalar: "\u232E",
        profline: "\u2312",
        profsurf: "\u2313",
        prop: "\u221D",
        Proportional: "\u221D",
        Proportion: "\u2237",
        propto: "\u221D",
        prsim: "\u227E",
        prurel: "\u22B0",
        Pscr: "\u{1D4AB}",
        pscr: "\u{1D4C5}",
        Psi: "\u03A8",
        psi: "\u03C8",
        puncsp: "\u2008",
        Qfr: "\u{1D514}",
        qfr: "\u{1D52E}",
        qint: "\u2A0C",
        qopf: "\u{1D562}",
        Qopf: "\u211A",
        qprime: "\u2057",
        Qscr: "\u{1D4AC}",
        qscr: "\u{1D4C6}",
        quaternions: "\u210D",
        quatint: "\u2A16",
        quest: "?",
        questeq: "\u225F",
        quot: '"',
        QUOT: '"',
        rAarr: "\u21DB",
        race: "\u223D\u0331",
        Racute: "\u0154",
        racute: "\u0155",
        radic: "\u221A",
        raemptyv: "\u29B3",
        rang: "\u27E9",
        Rang: "\u27EB",
        rangd: "\u2992",
        range: "\u29A5",
        rangle: "\u27E9",
        raquo: "\xBB",
        rarrap: "\u2975",
        rarrb: "\u21E5",
        rarrbfs: "\u2920",
        rarrc: "\u2933",
        rarr: "\u2192",
        Rarr: "\u21A0",
        rArr: "\u21D2",
        rarrfs: "\u291E",
        rarrhk: "\u21AA",
        rarrlp: "\u21AC",
        rarrpl: "\u2945",
        rarrsim: "\u2974",
        Rarrtl: "\u2916",
        rarrtl: "\u21A3",
        rarrw: "\u219D",
        ratail: "\u291A",
        rAtail: "\u291C",
        ratio: "\u2236",
        rationals: "\u211A",
        rbarr: "\u290D",
        rBarr: "\u290F",
        RBarr: "\u2910",
        rbbrk: "\u2773",
        rbrace: "}",
        rbrack: "]",
        rbrke: "\u298C",
        rbrksld: "\u298E",
        rbrkslu: "\u2990",
        Rcaron: "\u0158",
        rcaron: "\u0159",
        Rcedil: "\u0156",
        rcedil: "\u0157",
        rceil: "\u2309",
        rcub: "}",
        Rcy: "\u0420",
        rcy: "\u0440",
        rdca: "\u2937",
        rdldhar: "\u2969",
        rdquo: "\u201D",
        rdquor: "\u201D",
        rdsh: "\u21B3",
        real: "\u211C",
        realine: "\u211B",
        realpart: "\u211C",
        reals: "\u211D",
        Re: "\u211C",
        rect: "\u25AD",
        reg: "\xAE",
        REG: "\xAE",
        ReverseElement: "\u220B",
        ReverseEquilibrium: "\u21CB",
        ReverseUpEquilibrium: "\u296F",
        rfisht: "\u297D",
        rfloor: "\u230B",
        rfr: "\u{1D52F}",
        Rfr: "\u211C",
        rHar: "\u2964",
        rhard: "\u21C1",
        rharu: "\u21C0",
        rharul: "\u296C",
        Rho: "\u03A1",
        rho: "\u03C1",
        rhov: "\u03F1",
        RightAngleBracket: "\u27E9",
        RightArrowBar: "\u21E5",
        rightarrow: "\u2192",
        RightArrow: "\u2192",
        Rightarrow: "\u21D2",
        RightArrowLeftArrow: "\u21C4",
        rightarrowtail: "\u21A3",
        RightCeiling: "\u2309",
        RightDoubleBracket: "\u27E7",
        RightDownTeeVector: "\u295D",
        RightDownVectorBar: "\u2955",
        RightDownVector: "\u21C2",
        RightFloor: "\u230B",
        rightharpoondown: "\u21C1",
        rightharpoonup: "\u21C0",
        rightleftarrows: "\u21C4",
        rightleftharpoons: "\u21CC",
        rightrightarrows: "\u21C9",
        rightsquigarrow: "\u219D",
        RightTeeArrow: "\u21A6",
        RightTee: "\u22A2",
        RightTeeVector: "\u295B",
        rightthreetimes: "\u22CC",
        RightTriangleBar: "\u29D0",
        RightTriangle: "\u22B3",
        RightTriangleEqual: "\u22B5",
        RightUpDownVector: "\u294F",
        RightUpTeeVector: "\u295C",
        RightUpVectorBar: "\u2954",
        RightUpVector: "\u21BE",
        RightVectorBar: "\u2953",
        RightVector: "\u21C0",
        ring: "\u02DA",
        risingdotseq: "\u2253",
        rlarr: "\u21C4",
        rlhar: "\u21CC",
        rlm: "\u200F",
        rmoustache: "\u23B1",
        rmoust: "\u23B1",
        rnmid: "\u2AEE",
        roang: "\u27ED",
        roarr: "\u21FE",
        robrk: "\u27E7",
        ropar: "\u2986",
        ropf: "\u{1D563}",
        Ropf: "\u211D",
        roplus: "\u2A2E",
        rotimes: "\u2A35",
        RoundImplies: "\u2970",
        rpar: ")",
        rpargt: "\u2994",
        rppolint: "\u2A12",
        rrarr: "\u21C9",
        Rrightarrow: "\u21DB",
        rsaquo: "\u203A",
        rscr: "\u{1D4C7}",
        Rscr: "\u211B",
        rsh: "\u21B1",
        Rsh: "\u21B1",
        rsqb: "]",
        rsquo: "\u2019",
        rsquor: "\u2019",
        rthree: "\u22CC",
        rtimes: "\u22CA",
        rtri: "\u25B9",
        rtrie: "\u22B5",
        rtrif: "\u25B8",
        rtriltri: "\u29CE",
        RuleDelayed: "\u29F4",
        ruluhar: "\u2968",
        rx: "\u211E",
        Sacute: "\u015A",
        sacute: "\u015B",
        sbquo: "\u201A",
        scap: "\u2AB8",
        Scaron: "\u0160",
        scaron: "\u0161",
        Sc: "\u2ABC",
        sc: "\u227B",
        sccue: "\u227D",
        sce: "\u2AB0",
        scE: "\u2AB4",
        Scedil: "\u015E",
        scedil: "\u015F",
        Scirc: "\u015C",
        scirc: "\u015D",
        scnap: "\u2ABA",
        scnE: "\u2AB6",
        scnsim: "\u22E9",
        scpolint: "\u2A13",
        scsim: "\u227F",
        Scy: "\u0421",
        scy: "\u0441",
        sdotb: "\u22A1",
        sdot: "\u22C5",
        sdote: "\u2A66",
        searhk: "\u2925",
        searr: "\u2198",
        seArr: "\u21D8",
        searrow: "\u2198",
        sect: "\xA7",
        semi: ";",
        seswar: "\u2929",
        setminus: "\u2216",
        setmn: "\u2216",
        sext: "\u2736",
        Sfr: "\u{1D516}",
        sfr: "\u{1D530}",
        sfrown: "\u2322",
        sharp: "\u266F",
        SHCHcy: "\u0429",
        shchcy: "\u0449",
        SHcy: "\u0428",
        shcy: "\u0448",
        ShortDownArrow: "\u2193",
        ShortLeftArrow: "\u2190",
        shortmid: "\u2223",
        shortparallel: "\u2225",
        ShortRightArrow: "\u2192",
        ShortUpArrow: "\u2191",
        shy: "\xAD",
        Sigma: "\u03A3",
        sigma: "\u03C3",
        sigmaf: "\u03C2",
        sigmav: "\u03C2",
        sim: "\u223C",
        simdot: "\u2A6A",
        sime: "\u2243",
        simeq: "\u2243",
        simg: "\u2A9E",
        simgE: "\u2AA0",
        siml: "\u2A9D",
        simlE: "\u2A9F",
        simne: "\u2246",
        simplus: "\u2A24",
        simrarr: "\u2972",
        slarr: "\u2190",
        SmallCircle: "\u2218",
        smallsetminus: "\u2216",
        smashp: "\u2A33",
        smeparsl: "\u29E4",
        smid: "\u2223",
        smile: "\u2323",
        smt: "\u2AAA",
        smte: "\u2AAC",
        smtes: "\u2AAC\uFE00",
        SOFTcy: "\u042C",
        softcy: "\u044C",
        solbar: "\u233F",
        solb: "\u29C4",
        sol: "/",
        Sopf: "\u{1D54A}",
        sopf: "\u{1D564}",
        spades: "\u2660",
        spadesuit: "\u2660",
        spar: "\u2225",
        sqcap: "\u2293",
        sqcaps: "\u2293\uFE00",
        sqcup: "\u2294",
        sqcups: "\u2294\uFE00",
        Sqrt: "\u221A",
        sqsub: "\u228F",
        sqsube: "\u2291",
        sqsubset: "\u228F",
        sqsubseteq: "\u2291",
        sqsup: "\u2290",
        sqsupe: "\u2292",
        sqsupset: "\u2290",
        sqsupseteq: "\u2292",
        square: "\u25A1",
        Square: "\u25A1",
        SquareIntersection: "\u2293",
        SquareSubset: "\u228F",
        SquareSubsetEqual: "\u2291",
        SquareSuperset: "\u2290",
        SquareSupersetEqual: "\u2292",
        SquareUnion: "\u2294",
        squarf: "\u25AA",
        squ: "\u25A1",
        squf: "\u25AA",
        srarr: "\u2192",
        Sscr: "\u{1D4AE}",
        sscr: "\u{1D4C8}",
        ssetmn: "\u2216",
        ssmile: "\u2323",
        sstarf: "\u22C6",
        Star: "\u22C6",
        star: "\u2606",
        starf: "\u2605",
        straightepsilon: "\u03F5",
        straightphi: "\u03D5",
        strns: "\xAF",
        sub: "\u2282",
        Sub: "\u22D0",
        subdot: "\u2ABD",
        subE: "\u2AC5",
        sube: "\u2286",
        subedot: "\u2AC3",
        submult: "\u2AC1",
        subnE: "\u2ACB",
        subne: "\u228A",
        subplus: "\u2ABF",
        subrarr: "\u2979",
        subset: "\u2282",
        Subset: "\u22D0",
        subseteq: "\u2286",
        subseteqq: "\u2AC5",
        SubsetEqual: "\u2286",
        subsetneq: "\u228A",
        subsetneqq: "\u2ACB",
        subsim: "\u2AC7",
        subsub: "\u2AD5",
        subsup: "\u2AD3",
        succapprox: "\u2AB8",
        succ: "\u227B",
        succcurlyeq: "\u227D",
        Succeeds: "\u227B",
        SucceedsEqual: "\u2AB0",
        SucceedsSlantEqual: "\u227D",
        SucceedsTilde: "\u227F",
        succeq: "\u2AB0",
        succnapprox: "\u2ABA",
        succneqq: "\u2AB6",
        succnsim: "\u22E9",
        succsim: "\u227F",
        SuchThat: "\u220B",
        sum: "\u2211",
        Sum: "\u2211",
        sung: "\u266A",
        sup1: "\xB9",
        sup2: "\xB2",
        sup3: "\xB3",
        sup: "\u2283",
        Sup: "\u22D1",
        supdot: "\u2ABE",
        supdsub: "\u2AD8",
        supE: "\u2AC6",
        supe: "\u2287",
        supedot: "\u2AC4",
        Superset: "\u2283",
        SupersetEqual: "\u2287",
        suphsol: "\u27C9",
        suphsub: "\u2AD7",
        suplarr: "\u297B",
        supmult: "\u2AC2",
        supnE: "\u2ACC",
        supne: "\u228B",
        supplus: "\u2AC0",
        supset: "\u2283",
        Supset: "\u22D1",
        supseteq: "\u2287",
        supseteqq: "\u2AC6",
        supsetneq: "\u228B",
        supsetneqq: "\u2ACC",
        supsim: "\u2AC8",
        supsub: "\u2AD4",
        supsup: "\u2AD6",
        swarhk: "\u2926",
        swarr: "\u2199",
        swArr: "\u21D9",
        swarrow: "\u2199",
        swnwar: "\u292A",
        szlig: "\xDF",
        Tab: "	",
        target: "\u2316",
        Tau: "\u03A4",
        tau: "\u03C4",
        tbrk: "\u23B4",
        Tcaron: "\u0164",
        tcaron: "\u0165",
        Tcedil: "\u0162",
        tcedil: "\u0163",
        Tcy: "\u0422",
        tcy: "\u0442",
        tdot: "\u20DB",
        telrec: "\u2315",
        Tfr: "\u{1D517}",
        tfr: "\u{1D531}",
        there4: "\u2234",
        therefore: "\u2234",
        Therefore: "\u2234",
        Theta: "\u0398",
        theta: "\u03B8",
        thetasym: "\u03D1",
        thetav: "\u03D1",
        thickapprox: "\u2248",
        thicksim: "\u223C",
        ThickSpace: "\u205F\u200A",
        ThinSpace: "\u2009",
        thinsp: "\u2009",
        thkap: "\u2248",
        thksim: "\u223C",
        THORN: "\xDE",
        thorn: "\xFE",
        tilde: "\u02DC",
        Tilde: "\u223C",
        TildeEqual: "\u2243",
        TildeFullEqual: "\u2245",
        TildeTilde: "\u2248",
        timesbar: "\u2A31",
        timesb: "\u22A0",
        times: "\xD7",
        timesd: "\u2A30",
        tint: "\u222D",
        toea: "\u2928",
        topbot: "\u2336",
        topcir: "\u2AF1",
        top: "\u22A4",
        Topf: "\u{1D54B}",
        topf: "\u{1D565}",
        topfork: "\u2ADA",
        tosa: "\u2929",
        tprime: "\u2034",
        trade: "\u2122",
        TRADE: "\u2122",
        triangle: "\u25B5",
        triangledown: "\u25BF",
        triangleleft: "\u25C3",
        trianglelefteq: "\u22B4",
        triangleq: "\u225C",
        triangleright: "\u25B9",
        trianglerighteq: "\u22B5",
        tridot: "\u25EC",
        trie: "\u225C",
        triminus: "\u2A3A",
        TripleDot: "\u20DB",
        triplus: "\u2A39",
        trisb: "\u29CD",
        tritime: "\u2A3B",
        trpezium: "\u23E2",
        Tscr: "\u{1D4AF}",
        tscr: "\u{1D4C9}",
        TScy: "\u0426",
        tscy: "\u0446",
        TSHcy: "\u040B",
        tshcy: "\u045B",
        Tstrok: "\u0166",
        tstrok: "\u0167",
        twixt: "\u226C",
        twoheadleftarrow: "\u219E",
        twoheadrightarrow: "\u21A0",
        Uacute: "\xDA",
        uacute: "\xFA",
        uarr: "\u2191",
        Uarr: "\u219F",
        uArr: "\u21D1",
        Uarrocir: "\u2949",
        Ubrcy: "\u040E",
        ubrcy: "\u045E",
        Ubreve: "\u016C",
        ubreve: "\u016D",
        Ucirc: "\xDB",
        ucirc: "\xFB",
        Ucy: "\u0423",
        ucy: "\u0443",
        udarr: "\u21C5",
        Udblac: "\u0170",
        udblac: "\u0171",
        udhar: "\u296E",
        ufisht: "\u297E",
        Ufr: "\u{1D518}",
        ufr: "\u{1D532}",
        Ugrave: "\xD9",
        ugrave: "\xF9",
        uHar: "\u2963",
        uharl: "\u21BF",
        uharr: "\u21BE",
        uhblk: "\u2580",
        ulcorn: "\u231C",
        ulcorner: "\u231C",
        ulcrop: "\u230F",
        ultri: "\u25F8",
        Umacr: "\u016A",
        umacr: "\u016B",
        uml: "\xA8",
        UnderBar: "_",
        UnderBrace: "\u23DF",
        UnderBracket: "\u23B5",
        UnderParenthesis: "\u23DD",
        Union: "\u22C3",
        UnionPlus: "\u228E",
        Uogon: "\u0172",
        uogon: "\u0173",
        Uopf: "\u{1D54C}",
        uopf: "\u{1D566}",
        UpArrowBar: "\u2912",
        uparrow: "\u2191",
        UpArrow: "\u2191",
        Uparrow: "\u21D1",
        UpArrowDownArrow: "\u21C5",
        updownarrow: "\u2195",
        UpDownArrow: "\u2195",
        Updownarrow: "\u21D5",
        UpEquilibrium: "\u296E",
        upharpoonleft: "\u21BF",
        upharpoonright: "\u21BE",
        uplus: "\u228E",
        UpperLeftArrow: "\u2196",
        UpperRightArrow: "\u2197",
        upsi: "\u03C5",
        Upsi: "\u03D2",
        upsih: "\u03D2",
        Upsilon: "\u03A5",
        upsilon: "\u03C5",
        UpTeeArrow: "\u21A5",
        UpTee: "\u22A5",
        upuparrows: "\u21C8",
        urcorn: "\u231D",
        urcorner: "\u231D",
        urcrop: "\u230E",
        Uring: "\u016E",
        uring: "\u016F",
        urtri: "\u25F9",
        Uscr: "\u{1D4B0}",
        uscr: "\u{1D4CA}",
        utdot: "\u22F0",
        Utilde: "\u0168",
        utilde: "\u0169",
        utri: "\u25B5",
        utrif: "\u25B4",
        uuarr: "\u21C8",
        Uuml: "\xDC",
        uuml: "\xFC",
        uwangle: "\u29A7",
        vangrt: "\u299C",
        varepsilon: "\u03F5",
        varkappa: "\u03F0",
        varnothing: "\u2205",
        varphi: "\u03D5",
        varpi: "\u03D6",
        varpropto: "\u221D",
        varr: "\u2195",
        vArr: "\u21D5",
        varrho: "\u03F1",
        varsigma: "\u03C2",
        varsubsetneq: "\u228A\uFE00",
        varsubsetneqq: "\u2ACB\uFE00",
        varsupsetneq: "\u228B\uFE00",
        varsupsetneqq: "\u2ACC\uFE00",
        vartheta: "\u03D1",
        vartriangleleft: "\u22B2",
        vartriangleright: "\u22B3",
        vBar: "\u2AE8",
        Vbar: "\u2AEB",
        vBarv: "\u2AE9",
        Vcy: "\u0412",
        vcy: "\u0432",
        vdash: "\u22A2",
        vDash: "\u22A8",
        Vdash: "\u22A9",
        VDash: "\u22AB",
        Vdashl: "\u2AE6",
        veebar: "\u22BB",
        vee: "\u2228",
        Vee: "\u22C1",
        veeeq: "\u225A",
        vellip: "\u22EE",
        verbar: "|",
        Verbar: "\u2016",
        vert: "|",
        Vert: "\u2016",
        VerticalBar: "\u2223",
        VerticalLine: "|",
        VerticalSeparator: "\u2758",
        VerticalTilde: "\u2240",
        VeryThinSpace: "\u200A",
        Vfr: "\u{1D519}",
        vfr: "\u{1D533}",
        vltri: "\u22B2",
        vnsub: "\u2282\u20D2",
        vnsup: "\u2283\u20D2",
        Vopf: "\u{1D54D}",
        vopf: "\u{1D567}",
        vprop: "\u221D",
        vrtri: "\u22B3",
        Vscr: "\u{1D4B1}",
        vscr: "\u{1D4CB}",
        vsubnE: "\u2ACB\uFE00",
        vsubne: "\u228A\uFE00",
        vsupnE: "\u2ACC\uFE00",
        vsupne: "\u228B\uFE00",
        Vvdash: "\u22AA",
        vzigzag: "\u299A",
        Wcirc: "\u0174",
        wcirc: "\u0175",
        wedbar: "\u2A5F",
        wedge: "\u2227",
        Wedge: "\u22C0",
        wedgeq: "\u2259",
        weierp: "\u2118",
        Wfr: "\u{1D51A}",
        wfr: "\u{1D534}",
        Wopf: "\u{1D54E}",
        wopf: "\u{1D568}",
        wp: "\u2118",
        wr: "\u2240",
        wreath: "\u2240",
        Wscr: "\u{1D4B2}",
        wscr: "\u{1D4CC}",
        xcap: "\u22C2",
        xcirc: "\u25EF",
        xcup: "\u22C3",
        xdtri: "\u25BD",
        Xfr: "\u{1D51B}",
        xfr: "\u{1D535}",
        xharr: "\u27F7",
        xhArr: "\u27FA",
        Xi: "\u039E",
        xi: "\u03BE",
        xlarr: "\u27F5",
        xlArr: "\u27F8",
        xmap: "\u27FC",
        xnis: "\u22FB",
        xodot: "\u2A00",
        Xopf: "\u{1D54F}",
        xopf: "\u{1D569}",
        xoplus: "\u2A01",
        xotime: "\u2A02",
        xrarr: "\u27F6",
        xrArr: "\u27F9",
        Xscr: "\u{1D4B3}",
        xscr: "\u{1D4CD}",
        xsqcup: "\u2A06",
        xuplus: "\u2A04",
        xutri: "\u25B3",
        xvee: "\u22C1",
        xwedge: "\u22C0",
        Yacute: "\xDD",
        yacute: "\xFD",
        YAcy: "\u042F",
        yacy: "\u044F",
        Ycirc: "\u0176",
        ycirc: "\u0177",
        Ycy: "\u042B",
        ycy: "\u044B",
        yen: "\xA5",
        Yfr: "\u{1D51C}",
        yfr: "\u{1D536}",
        YIcy: "\u0407",
        yicy: "\u0457",
        Yopf: "\u{1D550}",
        yopf: "\u{1D56A}",
        Yscr: "\u{1D4B4}",
        yscr: "\u{1D4CE}",
        YUcy: "\u042E",
        yucy: "\u044E",
        yuml: "\xFF",
        Yuml: "\u0178",
        Zacute: "\u0179",
        zacute: "\u017A",
        Zcaron: "\u017D",
        zcaron: "\u017E",
        Zcy: "\u0417",
        zcy: "\u0437",
        Zdot: "\u017B",
        zdot: "\u017C",
        zeetrf: "\u2128",
        ZeroWidthSpace: "\u200B",
        Zeta: "\u0396",
        zeta: "\u03B6",
        zfr: "\u{1D537}",
        Zfr: "\u2128",
        ZHcy: "\u0416",
        zhcy: "\u0436",
        zigrarr: "\u21DD",
        zopf: "\u{1D56B}",
        Zopf: "\u2124",
        Zscr: "\u{1D4B5}",
        zscr: "\u{1D4CF}",
        zwj: "\u200D",
        zwnj: "\u200C"
    }
});
var Wr = _(($b, Ms) => {
    "use strict";
    Ms.exports = Is()
});
var oi = _((Ib, Fs) => {
    Fs.exports = /[!-#%-\*,-\/:;\?@\[-\]_\{\}\xA1\xA7\xAB\xB6\xB7\xBB\xBF\u037E\u0387\u055A-\u055F\u0589\u058A\u05BE\u05C0\u05C3\u05C6\u05F3\u05F4\u0609\u060A\u060C\u060D\u061B\u061E\u061F\u066A-\u066D\u06D4\u0700-\u070D\u07F7-\u07F9\u0830-\u083E\u085E\u0964\u0965\u0970\u09FD\u0A76\u0AF0\u0C84\u0DF4\u0E4F\u0E5A\u0E5B\u0F04-\u0F12\u0F14\u0F3A-\u0F3D\u0F85\u0FD0-\u0FD4\u0FD9\u0FDA\u104A-\u104F\u10FB\u1360-\u1368\u1400\u166D\u166E\u169B\u169C\u16EB-\u16ED\u1735\u1736\u17D4-\u17D6\u17D8-\u17DA\u1800-\u180A\u1944\u1945\u1A1E\u1A1F\u1AA0-\u1AA6\u1AA8-\u1AAD\u1B5A-\u1B60\u1BFC-\u1BFF\u1C3B-\u1C3F\u1C7E\u1C7F\u1CC0-\u1CC7\u1CD3\u2010-\u2027\u2030-\u2043\u2045-\u2051\u2053-\u205E\u207D\u207E\u208D\u208E\u2308-\u230B\u2329\u232A\u2768-\u2775\u27C5\u27C6\u27E6-\u27EF\u2983-\u2998\u29D8-\u29DB\u29FC\u29FD\u2CF9-\u2CFC\u2CFE\u2CFF\u2D70\u2E00-\u2E2E\u2E30-\u2E4E\u3001-\u3003\u3008-\u3011\u3014-\u301F\u3030\u303D\u30A0\u30FB\uA4FE\uA4FF\uA60D-\uA60F\uA673\uA67E\uA6F2-\uA6F7\uA874-\uA877\uA8CE\uA8CF\uA8F8-\uA8FA\uA8FC\uA92E\uA92F\uA95F\uA9C1-\uA9CD\uA9DE\uA9DF\uAA5C-\uAA5F\uAADE\uAADF\uAAF0\uAAF1\uABEB\uFD3E\uFD3F\uFE10-\uFE19\uFE30-\uFE52\uFE54-\uFE61\uFE63\uFE68\uFE6A\uFE6B\uFF01-\uFF03\uFF05-\uFF0A\uFF0C-\uFF0F\uFF1A\uFF1B\uFF1F\uFF20\uFF3B-\uFF3D\uFF3F\uFF5B\uFF5D\uFF5F-\uFF65]|\uD800[\uDD00-\uDD02\uDF9F\uDFD0]|\uD801\uDD6F|\uD802[\uDC57\uDD1F\uDD3F\uDE50-\uDE58\uDE7F\uDEF0-\uDEF6\uDF39-\uDF3F\uDF99-\uDF9C]|\uD803[\uDF55-\uDF59]|\uD804[\uDC47-\uDC4D\uDCBB\uDCBC\uDCBE-\uDCC1\uDD40-\uDD43\uDD74\uDD75\uDDC5-\uDDC8\uDDCD\uDDDB\uDDDD-\uDDDF\uDE38-\uDE3D\uDEA9]|\uD805[\uDC4B-\uDC4F\uDC5B\uDC5D\uDCC6\uDDC1-\uDDD7\uDE41-\uDE43\uDE60-\uDE6C\uDF3C-\uDF3E]|\uD806[\uDC3B\uDE3F-\uDE46\uDE9A-\uDE9C\uDE9E-\uDEA2]|\uD807[\uDC41-\uDC45\uDC70\uDC71\uDEF7\uDEF8]|\uD809[\uDC70-\uDC74]|\uD81A[\uDE6E\uDE6F\uDEF5\uDF37-\uDF3B\uDF44]|\uD81B[\uDE97-\uDE9A]|\uD82F\uDC9F|\uD836[\uDE87-\uDE8B]|\uD83A[\uDD5E\uDD5F]/
});
var Ps = _((Mb, Bs) => {
    "use strict";
    var qs = {};

    function qh(n) {
        var t, e, i = qs[n];
        if (i) return i;
        for (i = qs[n] = [], t = 0; t < 128; t++) e = String.fromCharCode(t), /^[0-9a-z]$/i.test(e) ? i.push(e) : i.push("%" + ("0" + t.toString(16).toUpperCase()).slice(-2));
        for (t = 0; t < n.length; t++) i[n.charCodeAt(t)] = n[t];
        return i
    }

    function si(n, t, e) {
        var i, r, o, s, a, l = "";
        for (typeof t != "string" && (e = t, t = si.defaultChars), typeof e > "u" && (e = !0), a = qh(t), i = 0, r = n.length; i < r; i++) {
            if (o = n.charCodeAt(i), e && o === 37 && i + 2 < r && /^[0-9a-f]{2}$/i.test(n.slice(i + 1, i + 3))) {
                l += n.slice(i, i + 3), i += 2;
                continue
            }
            if (o < 128) {
                l += a[o];
                continue
            }
            if (o >= 55296 && o <= 57343) {
                if (o >= 55296 && o <= 56319 && i + 1 < r && (s = n.charCodeAt(i + 1), s >= 56320 && s <= 57343)) {
                    l += encodeURIComponent(n[i] + n[i + 1]), i++;
                    continue
                }
                l += "%EF%BF%BD";
                continue
            }
            l += encodeURIComponent(n[i])
        }
        return l
    }
    si.defaultChars = ";/?:@&=+$,-_.!~*'()#";
    si.componentChars = "-_.!~*'()";
    Bs.exports = si
});
var Ns = _((Fb, Rs) => {
    "use strict";
    var Os = {};

    function Bh(n) {
        var t, e, i = Os[n];
        if (i) return i;
        for (i = Os[n] = [], t = 0; t < 128; t++) e = String.fromCharCode(t), i.push(e);
        for (t = 0; t < n.length; t++) e = n.charCodeAt(t), i[e] = "%" + ("0" + e.toString(16).toUpperCase()).slice(-2);
        return i
    }

    function ai(n, t) {
        var e;
        return typeof t != "string" && (t = ai.defaultChars), e = Bh(t), n.replace(/(%[a-f0-9]{2})+/gi, function(i) {
            var r, o, s, a, l, c, u, h = "";
            for (r = 0, o = i.length; r < o; r += 3) {
                if (s = parseInt(i.slice(r + 1, r + 3), 16), s < 128) {
                    h += e[s];
                    continue
                }
                if ((s & 224) === 192 && r + 3 < o && (a = parseInt(i.slice(r + 4, r + 6), 16), (a & 192) === 128)) {
                    u = s << 6 & 1984 | a & 63, u < 128 ? h += "\uFFFD\uFFFD" : h += String.fromCharCode(u), r += 3;
                    continue
                }
                if ((s & 240) === 224 && r + 6 < o && (a = parseInt(i.slice(r + 4, r + 6), 16), l = parseInt(i.slice(r + 7, r + 9), 16), (a & 192) === 128 && (l & 192) === 128)) {
                    u = s << 12 & 61440 | a << 6 & 4032 | l & 63, u < 2048 || u >= 55296 && u <= 57343 ? h += "\uFFFD\uFFFD\uFFFD" : h += String.fromCharCode(u), r += 6;
                    continue
                }
                if ((s & 248) === 240 && r + 9 < o && (a = parseInt(i.slice(r + 4, r + 6), 16), l = parseInt(i.slice(r + 7, r + 9), 16), c = parseInt(i.slice(r + 10, r + 12), 16), (a & 192) === 128 && (l & 192) === 128 && (c & 192) === 128)) {
                    u = s << 18 & 1835008 | a << 12 & 258048 | l << 6 & 4032 | c & 63, u < 65536 || u > 1114111 ? h += "\uFFFD\uFFFD\uFFFD\uFFFD" : (u -= 65536, h += String.fromCharCode(55296 + (u >> 10), 56320 + (u & 1023))), r += 9;
                    continue
                }
                h += "\uFFFD"
            }
            return h
        })
    }
    ai.defaultChars = ";/?:@&=+$,#";
    ai.componentChars = "";
    Rs.exports = ai
});
var Hs = _((qb, zs) => {
    "use strict";
    zs.exports = function(t) {
        var e = "";
        return e += t.protocol || "", e += t.slashes ? "//" : "", e += t.auth ? t.auth + "@" : "", t.hostname && t.hostname.indexOf(":") !== -1 ? e += "[" + t.hostname + "]" : e += t.hostname || "", e += t.port ? ":" + t.port : "", e += t.pathname || "", e += t.search || "", e += t.hash || "", e
    }
});
var Zs = _((Bb, Ks) => {
    "use strict";

    function li() {
        this.protocol = null, this.slashes = null, this.auth = null, this.port = null, this.hostname = null, this.hash = null, this.search = null, this.pathname = null
    }
    var Ph = /^([a-z0-9.+-]+:)/i,
        Oh = /:[0-9]*$/,
        Rh = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,
        Nh = ["<", ">", '"', "`", " ", "\r", `
`, "	"],
        zh = ["{", "}", "|", "\\", "^", "`"].concat(Nh),
        Hh = ["'"].concat(zh),
        Us = ["%", "/", "?", ";", "#"].concat(Hh),
        js = ["/", "?", "#"],
        Uh = 255,
        Vs = /^[+a-z0-9A-Z_-]{0,63}$/,
        jh = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,
        Ws = {
            javascript: !0,
            "javascript:": !0
        },
        Gs = {
            http: !0,
            https: !0,
            ftp: !0,
            gopher: !0,
            file: !0,
            "http:": !0,
            "https:": !0,
            "ftp:": !0,
            "gopher:": !0,
            "file:": !0
        };

    function Vh(n, t) {
        if (n && n instanceof li) return n;
        var e = new li;
        return e.parse(n, t), e
    }
    li.prototype.parse = function(n, t) {
        var e, i, r, o, s, a = n;
        if (a = a.trim(), !t && n.split("#").length === 1) {
            var l = Rh.exec(a);
            if (l) return this.pathname = l[1], l[2] && (this.search = l[2]), this
        }
        var c = Ph.exec(a);
        if (c && (c = c[0], r = c.toLowerCase(), this.protocol = c, a = a.substr(c.length)), (t || c || a.match(/^\/\/[^@\/]+@[^@\/]+/)) && (s = a.substr(0, 2) === "//", s && !(c && Ws[c]) && (a = a.substr(2), this.slashes = !0)), !Ws[c] && (s || c && !Gs[c])) {
            var u = -1;
            for (e = 0; e < js.length; e++) o = a.indexOf(js[e]), o !== -1 && (u === -1 || o < u) && (u = o);
            var h, d;
            for (u === -1 ? d = a.lastIndexOf("@") : d = a.lastIndexOf("@", u), d !== -1 && (h = a.slice(0, d), a = a.slice(d + 1), this.auth = h), u = -1, e = 0; e < Us.length; e++) o = a.indexOf(Us[e]), o !== -1 && (u === -1 || o < u) && (u = o);
            u === -1 && (u = a.length), a[u - 1] === ":" && u--;
            var f = a.slice(0, u);
            a = a.slice(u), this.parseHost(f), this.hostname = this.hostname || "";
            var p = this.hostname[0] === "[" && this.hostname[this.hostname.length - 1] === "]";
            if (!p) {
                var m = this.hostname.split(/\./);
                for (e = 0, i = m.length; e < i; e++) {
                    var w = m[e];
                    if (w && !w.match(Vs)) {
                        for (var v = "", b = 0, k = w.length; b < k; b++) w.charCodeAt(b) > 127 ? v += "x" : v += w[b];
                        if (!v.match(Vs)) {
                            var x = m.slice(0, e),
                                E = m.slice(e + 1),
                                y = w.match(jh);
                            y && (x.push(y[1]), E.unshift(y[2])), E.length && (a = E.join(".") + a), this.hostname = x.join(".");
                            break
                        }
                    }
                }
            }
            this.hostname.length > Uh && (this.hostname = ""), p && (this.hostname = this.hostname.substr(1, this.hostname.length - 2))
        }
        var S = a.indexOf("#");
        S !== -1 && (this.hash = a.substr(S), a = a.slice(0, S));
        var D = a.indexOf("?");
        return D !== -1 && (this.search = a.substr(D), a = a.slice(0, D)), a && (this.pathname = a), Gs[r] && this.hostname && !this.pathname && (this.pathname = ""), this
    };
    li.prototype.parseHost = function(n) {
        var t = Oh.exec(n);
        t && (t = t[0], t !== ":" && (this.port = t.substr(1)), n = n.substr(0, n.length - t.length)), n && (this.hostname = n)
    };
    Ks.exports = Vh
});
var Gr = _((Pb, Ke) => {
    "use strict";
    Ke.exports.encode = Ps();
    Ke.exports.decode = Ns();
    Ke.exports.format = Hs();
    Ke.exports.parse = Zs()
});
var Kr = _((Ob, Xs) => {
    Xs.exports = /[\0-\uD7FF\uE000-\uFFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/
});
var Zr = _((Rb, Ys) => {
    Ys.exports = /[\0-\x1F\x7F-\x9F]/
});
var Qs = _((Nb, Js) => {
    Js.exports = /[\xAD\u0600-\u0605\u061C\u06DD\u070F\u08E2\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]|\uD804[\uDCBD\uDCCD]|\uD82F[\uDCA0-\uDCA3]|\uD834[\uDD73-\uDD7A]|\uDB40[\uDC01\uDC20-\uDC7F]/
});
var Xr = _((zb, ta) => {
    ta.exports = /[ \xA0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/
});
var ea = _(ge => {
    "use strict";
    ge.Any = Kr();
    ge.Cc = Zr();
    ge.Cf = Qs();
    ge.P = oi();
    ge.Z = Xr()
});
var N = _(Q => {
    "use strict";

    function Wh(n) {
        return Object.prototype.toString.call(n)
    }

    function Gh(n) {
        return Wh(n) === "[object String]"
    }
    var Kh = Object.prototype.hasOwnProperty;

    function ia(n, t) {
        return Kh.call(n, t)
    }

    function Zh(n) {
        var t = Array.prototype.slice.call(arguments, 1);
        return t.forEach(function(e) {
            if (e) {
                if (typeof e != "object") throw new TypeError(e + "must be object");
                Object.keys(e).forEach(function(i) {
                    n[i] = e[i]
                })
            }
        }), n
    }

    function Xh(n, t, e) {
        return [].concat(n.slice(0, t), e, n.slice(t + 1))
    }

    function ra(n) {
        return !(n >= 55296 && n <= 57343 || n >= 64976 && n <= 65007 || (n & 65535) === 65535 || (n & 65535) === 65534 || n >= 0 && n <= 8 || n === 11 || n >= 14 && n <= 31 || n >= 127 && n <= 159 || n > 1114111)
    }

    function oa(n) {
        if (n > 65535) {
            n -= 65536;
            var t = 55296 + (n >> 10),
                e = 56320 + (n & 1023);
            return String.fromCharCode(t, e)
        }
        return String.fromCharCode(n)
    }
    var sa = /\\([!"#$%&'()*+,\-.\/:;<=>?@[\\\]^_`{|}~])/g,
        Yh = /&([a-z#][a-z0-9]{1,31});/gi,
        Jh = new RegExp(sa.source + "|" + Yh.source, "gi"),
        Qh = /^#((?:x[a-f0-9]{1,8}|[0-9]{1,8}))$/i,
        na = Wr();

    function td(n, t) {
        var e;
        return ia(na, t) ? na[t] : t.charCodeAt(0) === 35 && Qh.test(t) && (e = t[1].toLowerCase() === "x" ? parseInt(t.slice(2), 16) : parseInt(t.slice(1), 10), ra(e)) ? oa(e) : n
    }

    function ed(n) {
        return n.indexOf("\\") < 0 ? n : n.replace(sa, "$1")
    }

    function nd(n) {
        return n.indexOf("\\") < 0 && n.indexOf("&") < 0 ? n : n.replace(Jh, function(t, e, i) {
            return e || td(t, i)
        })
    }
    var id = /[&<>"]/,
        rd = /[&<>"]/g,
        od = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;"
        };

    function sd(n) {
        return od[n]
    }

    function ad(n) {
        return id.test(n) ? n.replace(rd, sd) : n
    }
    var ld = /[.?*+^$[\]\\(){}|-]/g;

    function cd(n) {
        return n.replace(ld, "\\$&")
    }

    function ud(n) {
        switch (n) {
            case 9:
            case 32:
                return !0
        }
        return !1
    }

    function hd(n) {
        if (n >= 8192 && n <= 8202) return !0;
        switch (n) {
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 32:
            case 160:
            case 5760:
            case 8239:
            case 8287:
            case 12288:
                return !0
        }
        return !1
    }
    var dd = oi();

    function pd(n) {
        return dd.test(n)
    }

    function fd(n) {
        switch (n) {
            case 33:
            case 34:
            case 35:
            case 36:
            case 37:
            case 38:
            case 39:
            case 40:
            case 41:
            case 42:
            case 43:
            case 44:
            case 45:
            case 46:
            case 47:
            case 58:
            case 59:
            case 60:
            case 61:
            case 62:
            case 63:
            case 64:
            case 91:
            case 92:
            case 93:
            case 94:
            case 95:
            case 96:
            case 123:
            case 124:
            case 125:
            case 126:
                return !0;
            default:
                return !1
        }
    }

    function md(n) {
        return n = n.trim().replace(/\s+/g, " "), "\u1E9E".toLowerCase() === "\u1E7E" && (n = n.replace(/áºž/g, "\xDF")), n.toLowerCase().toUpperCase()
    }
    Q.lib = {};
    Q.lib.mdurl = Gr();
    Q.lib.ucmicro = ea();
    Q.assign = Zh;
    Q.isString = Gh;
    Q.has = ia;
    Q.unescapeMd = ed;
    Q.unescapeAll = nd;
    Q.isValidEntityCode = ra;
    Q.fromCodePoint = oa;
    Q.escapeHtml = ad;
    Q.arrayReplaceAt = Xh;
    Q.isSpace = ud;
    Q.isWhiteSpace = hd;
    Q.isMdAsciiPunct = fd;
    Q.isPunctChar = pd;
    Q.escapeRE = cd;
    Q.normalizeReference = md
});
var la = _((jb, aa) => {
    "use strict";
    aa.exports = function(t, e, i) {
        var r, o, s, a, l = -1,
            c = t.posMax,
            u = t.pos;
        for (t.pos = e + 1, r = 1; t.pos < c;) {
            if (s = t.src.charCodeAt(t.pos), s === 93 && (r--, r === 0)) {
                o = !0;
                break
            }
            if (a = t.pos, t.md.inline.skipToken(t), s === 91) {
                if (a === t.pos - 1) r++;
                else if (i) return t.pos = u, -1
            }
        }
        return o && (l = t.pos), t.pos = u, l
    }
});
var ha = _((Vb, ua) => {
    "use strict";
    var ca = N().unescapeAll;
    ua.exports = function(t, e, i) {
        var r, o, s = e,
            a = {
                ok: !1,
                pos: 0,
                lines: 0,
                str: ""
            };
        if (t.charCodeAt(s) === 60) {
            for (s++; s < i;) {
                if (r = t.charCodeAt(s), r === 10 || r === 60) return a;
                if (r === 62) return a.pos = s + 1, a.str = ca(t.slice(e + 1, s)), a.ok = !0, a;
                if (r === 92 && s + 1 < i) {
                    s += 2;
                    continue
                }
                s++
            }
            return a
        }
        for (o = 0; s < i && (r = t.charCodeAt(s), !(r === 32 || r < 32 || r === 127));) {
            if (r === 92 && s + 1 < i) {
                if (t.charCodeAt(s + 1) === 32) break;
                s += 2;
                continue
            }
            if (r === 40 && (o++, o > 32)) return a;
            if (r === 41) {
                if (o === 0) break;
                o--
            }
            s++
        }
        return e === s || o !== 0 || (a.str = ca(t.slice(e, s)), a.pos = s, a.ok = !0), a
    }
});
var pa = _((Wb, da) => {
    "use strict";
    var gd = N().unescapeAll;
    da.exports = function(t, e, i) {
        var r, o, s = 0,
            a = e,
            l = {
                ok: !1,
                pos: 0,
                lines: 0,
                str: ""
            };
        if (a >= i || (o = t.charCodeAt(a), o !== 34 && o !== 39 && o !== 40)) return l;
        for (a++, o === 40 && (o = 41); a < i;) {
            if (r = t.charCodeAt(a), r === o) return l.pos = a + 1, l.lines = s, l.str = gd(t.slice(e + 1, a)), l.ok = !0, l;
            if (r === 40 && o === 41) return l;
            r === 10 ? s++ : r === 92 && a + 1 < i && (a++, t.charCodeAt(a) === 10 && s++), a++
        }
        return l
    }
});
var fa = _(ci => {
    "use strict";
    ci.parseLinkLabel = la();
    ci.parseLinkDestination = ha();
    ci.parseLinkTitle = pa()
});
var ga = _((Kb, ma) => {
    "use strict";
    var bd = N().assign,
        vd = N().unescapeAll,
        Jt = N().escapeHtml,
        Dt = {};
    Dt.code_inline = function(n, t, e, i, r) {
        var o = n[t];
        return "<code" + r.renderAttrs(o) + ">" + Jt(o.content) + "</code>"
    };
    Dt.code_block = function(n, t, e, i, r) {
        var o = n[t];
        return "<pre" + r.renderAttrs(o) + "><code>" + Jt(n[t].content) + `</code></pre>
`
    };
    Dt.fence = function(n, t, e, i, r) {
        var o = n[t],
            s = o.info ? vd(o.info).trim() : "",
            a = "",
            l = "",
            c, u, h, d, f;
        return s && (h = s.split(/(\s+)/g), a = h[0], l = h.slice(2).join("")), e.highlight ? c = e.highlight(o.content, a, l) || Jt(o.content) : c = Jt(o.content), c.indexOf("<pre") === 0 ? c + `
` : s ? (u = o.attrIndex("class"), d = o.attrs ? o.attrs.slice() : [], u < 0 ? d.push(["class", e.langPrefix + a]) : (d[u] = d[u].slice(), d[u][1] += " " + e.langPrefix + a), f = {
            attrs: d
        }, "<pre><code" + r.renderAttrs(f) + ">" + c + `</code></pre>
`) : "<pre><code" + r.renderAttrs(o) + ">" + c + `</code></pre>
`
    };
    Dt.image = function(n, t, e, i, r) {
        var o = n[t];
        return o.attrs[o.attrIndex("alt")][1] = r.renderInlineAsText(o.children, e, i), r.renderToken(n, t, e)
    };
    Dt.hardbreak = function(n, t, e) {
        return e.xhtmlOut ? `<br />
` : `<br>
`
    };
    Dt.softbreak = function(n, t, e) {
        return e.breaks ? e.xhtmlOut ? `<br />
` : `<br>
` : `
`
    };
    Dt.text = function(n, t) {
        return Jt(n[t].content)
    };
    Dt.html_block = function(n, t) {
        return n[t].content
    };
    Dt.html_inline = function(n, t) {
        return n[t].content
    };

    function be() {
        this.rules = bd({}, Dt)
    }
    be.prototype.renderAttrs = function(t) {
        var e, i, r;
        if (!t.attrs) return "";
        for (r = "", e = 0, i = t.attrs.length; e < i; e++) r += " " + Jt(t.attrs[e][0]) + '="' + Jt(t.attrs[e][1]) + '"';
        return r
    };
    be.prototype.renderToken = function(t, e, i) {
        var r, o = "",
            s = !1,
            a = t[e];
        return a.hidden ? "" : (a.block && a.nesting !== -1 && e && t[e - 1].hidden && (o += `
`), o += (a.nesting === -1 ? "</" : "<") + a.tag, o += this.renderAttrs(a), a.nesting === 0 && i.xhtmlOut && (o += " /"), a.block && (s = !0, a.nesting === 1 && e + 1 < t.length && (r = t[e + 1], (r.type === "inline" || r.hidden || r.nesting === -1 && r.tag === a.tag) && (s = !1))), o += s ? `>
` : ">", o)
    };
    be.prototype.renderInline = function(n, t, e) {
        for (var i, r = "", o = this.rules, s = 0, a = n.length; s < a; s++) i = n[s].type, typeof o[i] < "u" ? r += o[i](n, s, t, e, this) : r += this.renderToken(n, s, t);
        return r
    };
    be.prototype.renderInlineAsText = function(n, t, e) {
        for (var i = "", r = 0, o = n.length; r < o; r++) n[r].type === "text" ? i += n[r].content : n[r].type === "image" ? i += this.renderInlineAsText(n[r].children, t, e) : n[r].type === "softbreak" && (i += `
`);
        return i
    };
    be.prototype.render = function(n, t, e) {
        var i, r, o, s = "",
            a = this.rules;
        for (i = 0, r = n.length; i < r; i++) o = n[i].type, o === "inline" ? s += this.renderInline(n[i].children, t, e) : typeof a[o] < "u" ? s += a[o](n, i, t, e, this) : s += this.renderToken(n, i, t, e);
        return s
    };
    ma.exports = be
});
var ui = _((Zb, ba) => {
    "use strict";

    function Ct() {
        this.__rules__ = [], this.__cache__ = null
    }
    Ct.prototype.__find__ = function(n) {
        for (var t = 0; t < this.__rules__.length; t++)
            if (this.__rules__[t].name === n) return t;
        return -1
    };
    Ct.prototype.__compile__ = function() {
        var n = this,
            t = [""];
        n.__rules__.forEach(function(e) {
            e.enabled && e.alt.forEach(function(i) {
                t.indexOf(i) < 0 && t.push(i)
            })
        }), n.__cache__ = {}, t.forEach(function(e) {
            n.__cache__[e] = [], n.__rules__.forEach(function(i) {
                i.enabled && (e && i.alt.indexOf(e) < 0 || n.__cache__[e].push(i.fn))
            })
        })
    };
    Ct.prototype.at = function(n, t, e) {
        var i = this.__find__(n),
            r = e || {};
        if (i === -1) throw new Error("Parser rule not found: " + n);
        this.__rules__[i].fn = t, this.__rules__[i].alt = r.alt || [], this.__cache__ = null
    };
    Ct.prototype.before = function(n, t, e, i) {
        var r = this.__find__(n),
            o = i || {};
        if (r === -1) throw new Error("Parser rule not found: " + n);
        this.__rules__.splice(r, 0, {
            name: t,
            enabled: !0,
            fn: e,
            alt: o.alt || []
        }), this.__cache__ = null
    };
    Ct.prototype.after = function(n, t, e, i) {
        var r = this.__find__(n),
            o = i || {};
        if (r === -1) throw new Error("Parser rule not found: " + n);
        this.__rules__.splice(r + 1, 0, {
            name: t,
            enabled: !0,
            fn: e,
            alt: o.alt || []
        }), this.__cache__ = null
    };
    Ct.prototype.push = function(n, t, e) {
        var i = e || {};
        this.__rules__.push({
            name: n,
            enabled: !0,
            fn: t,
            alt: i.alt || []
        }), this.__cache__ = null
    };
    Ct.prototype.enable = function(n, t) {
        Array.isArray(n) || (n = [n]);
        var e = [];
        return n.forEach(function(i) {
            var r = this.__find__(i);
            if (r < 0) {
                if (t) return;
                throw new Error("Rules manager: invalid rule name " + i)
            }
            this.__rules__[r].enabled = !0, e.push(i)
        }, this), this.__cache__ = null, e
    };
    Ct.prototype.enableOnly = function(n, t) {
        Array.isArray(n) || (n = [n]), this.__rules__.forEach(function(e) {
            e.enabled = !1
        }), this.enable(n, t)
    };
    Ct.prototype.disable = function(n, t) {
        Array.isArray(n) || (n = [n]);
        var e = [];
        return n.forEach(function(i) {
            var r = this.__find__(i);
            if (r < 0) {
                if (t) return;
                throw new Error("Rules manager: invalid rule name " + i)
            }
            this.__rules__[r].enabled = !1, e.push(i)
        }, this), this.__cache__ = null, e
    };
    Ct.prototype.getRules = function(n) {
        return this.__cache__ === null && this.__compile__(), this.__cache__[n] || []
    };
    ba.exports = Ct
});
var wa = _((Xb, va) => {
    "use strict";
    var wd = /\r\n?|\n/g,
        yd = /\0/g;
    va.exports = function(t) {
        var e;
        e = t.src.replace(wd, `
`), e = e.replace(yd, "\uFFFD"), t.src = e
    }
});
var xa = _((Yb, ya) => {
    "use strict";
    ya.exports = function(t) {
        var e;
        t.inlineMode ? (e = new t.Token("inline", "", 0), e.content = t.src, e.map = [0, 1], e.children = [], t.tokens.push(e)) : t.md.block.parse(t.src, t.md, t.env, t.tokens)
    }
});
var Ca = _((Jb, ka) => {
    "use strict";
    ka.exports = function(t) {
        var e = t.tokens,
            i, r, o;
        for (r = 0, o = e.length; r < o; r++) i = e[r], i.type === "inline" && t.md.inline.parse(i.content, t.md, t.env, i.children)
    }
});
var _a = _((Qb, Ea) => {
    "use strict";
    var xd = N().arrayReplaceAt;

    function kd(n) {
        return /^<a[>\s]/i.test(n)
    }

    function Cd(n) {
        return /^<\/a\s*>/i.test(n)
    }
    Ea.exports = function(t) {
        var e, i, r, o, s, a, l, c, u, h, d, f, p, m, w, v, b = t.tokens,
            k;
        if (t.md.options.linkify) {
            for (i = 0, r = b.length; i < r; i++)
                if (!(b[i].type !== "inline" || !t.md.linkify.pretest(b[i].content)))
                    for (o = b[i].children, p = 0, e = o.length - 1; e >= 0; e--) {
                        if (a = o[e], a.type === "link_close") {
                            for (e--; o[e].level !== a.level && o[e].type !== "link_open";) e--;
                            continue
                        }
                        if (a.type === "html_inline" && (kd(a.content) && p > 0 && p--, Cd(a.content) && p++), !(p > 0) && a.type === "text" && t.md.linkify.test(a.content)) {
                            for (u = a.content, k = t.md.linkify.match(u), l = [], f = a.level, d = 0, k.length > 0 && k[0].index === 0 && e > 0 && o[e - 1].type === "text_special" && (k = k.slice(1)), c = 0; c < k.length; c++) m = k[c].url, w = t.md.normalizeLink(m), t.md.validateLink(w) && (v = k[c].text, k[c].schema ? k[c].schema === "mailto:" && !/^mailto:/i.test(v) ? v = t.md.normalizeLinkText("mailto:" + v).replace(/^mailto:/, "") : v = t.md.normalizeLinkText(v) : v = t.md.normalizeLinkText("http://" + v).replace(/^http:\/\//, ""), h = k[c].index, h > d && (s = new t.Token("text", "", 0), s.content = u.slice(d, h), s.level = f, l.push(s)), s = new t.Token("link_open", "a", 1), s.attrs = [
                                ["href", w]
                            ], s.level = f++, s.markup = "linkify", s.info = "auto", l.push(s), s = new t.Token("text", "", 0), s.content = v, s.level = f, l.push(s), s = new t.Token("link_close", "a", -1), s.level = --f, s.markup = "linkify", s.info = "auto", l.push(s), d = k[c].lastIndex);
                            d < u.length && (s = new t.Token("text", "", 0), s.content = u.slice(d), s.level = f, l.push(s)), b[i].children = o = xd(o, e, l)
                        }
                    }
        }
    }
});
var Da = _((tv, Aa) => {
    "use strict";
    var Sa = /\+-|\.\.|\?\?\?\?|!!!!|,,|--/,
        Ed = /\((c|tm|r)\)/i,
        _d = /\((c|tm|r)\)/ig,
        Sd = {
            c: "\xA9",
            r: "\xAE",
            tm: "\u2122"
        };

    function Ad(n, t) {
        return Sd[t.toLowerCase()]
    }

    function Dd(n) {
        var t, e, i = 0;
        for (t = n.length - 1; t >= 0; t--) e = n[t], e.type === "text" && !i && (e.content = e.content.replace(_d, Ad)), e.type === "link_open" && e.info === "auto" && i--, e.type === "link_close" && e.info === "auto" && i++
    }

    function Ld(n) {
        var t, e, i = 0;
        for (t = n.length - 1; t >= 0; t--) e = n[t], e.type === "text" && !i && Sa.test(e.content) && (e.content = e.content.replace(/\+-/g, "\xB1").replace(/\.{2,}/g, "\u2026").replace(/([?!])â€¦/g, "$1..").replace(/([?!]){4,}/g, "$1$1$1").replace(/,{2,}/g, ",").replace(/(^|[^-])---(?=[^-]|$)/mg, "$1\u2014").replace(/(^|\s)--(?=\s|$)/mg, "$1\u2013").replace(/(^|[^-\s])--(?=[^-\s]|$)/mg, "$1\u2013")), e.type === "link_open" && e.info === "auto" && i--, e.type === "link_close" && e.info === "auto" && i++
    }
    Aa.exports = function(t) {
        var e;
        if (t.md.options.typographer)
            for (e = t.tokens.length - 1; e >= 0; e--) t.tokens[e].type === "inline" && (Ed.test(t.tokens[e].content) && Dd(t.tokens[e].children), Sa.test(t.tokens[e].content) && Ld(t.tokens[e].children))
    }
});
var qa = _((ev, Fa) => {
    "use strict";
    var La = N().isWhiteSpace,
        Ta = N().isPunctChar,
        $a = N().isMdAsciiPunct,
        Td = /['"]/,
        Ia = /['"]/g,
        Ma = "\u2019";

    function hi(n, t, e) {
        return n.slice(0, t) + e + n.slice(t + 1)
    }

    function $d(n, t) {
        var e, i, r, o, s, a, l, c, u, h, d, f, p, m, w, v, b, k, x, E, y;
        for (x = [], e = 0; e < n.length; e++) {
            for (i = n[e], l = n[e].level, b = x.length - 1; b >= 0 && !(x[b].level <= l); b--);
            if (x.length = b + 1, i.type === "text") {
                r = i.content, s = 0, a = r.length;
                t: for (; s < a && (Ia.lastIndex = s, o = Ia.exec(r), !!o);) {
                    if (w = v = !0, s = o.index + 1, k = o[0] === "'", u = 32, o.index - 1 >= 0) u = r.charCodeAt(o.index - 1);
                    else
                        for (b = e - 1; b >= 0 && !(n[b].type === "softbreak" || n[b].type === "hardbreak"); b--)
                            if (n[b].content) {
                                u = n[b].content.charCodeAt(n[b].content.length - 1);
                                break
                            } if (h = 32, s < a) h = r.charCodeAt(s);
                    else
                        for (b = e + 1; b < n.length && !(n[b].type === "softbreak" || n[b].type === "hardbreak"); b++)
                            if (n[b].content) {
                                h = n[b].content.charCodeAt(0);
                                break
                            } if (d = $a(u) || Ta(String.fromCharCode(u)), f = $a(h) || Ta(String.fromCharCode(h)), p = La(u), m = La(h), m ? w = !1 : f && (p || d || (w = !1)), p ? v = !1 : d && (m || f || (v = !1)), h === 34 && o[0] === '"' && u >= 48 && u <= 57 && (v = w = !1), w && v && (w = d, v = f), !w && !v) {
                        k && (i.content = hi(i.content, o.index, Ma));
                        continue
                    }
                    if (v) {
                        for (b = x.length - 1; b >= 0 && (c = x[b], !(x[b].level < l)); b--)
                            if (c.single === k && x[b].level === l) {
                                c = x[b], k ? (E = t.md.options.quotes[2], y = t.md.options.quotes[3]) : (E = t.md.options.quotes[0], y = t.md.options.quotes[1]), i.content = hi(i.content, o.index, y), n[c.token].content = hi(n[c.token].content, c.pos, E), s += y.length - 1, c.token === e && (s += E.length - 1), r = i.content, a = r.length, x.length = b;
                                continue t
                            }
                    }
                    w ? x.push({
                        token: e,
                        pos: o.index,
                        single: k,
                        level: l
                    }) : v && k && (i.content = hi(i.content, o.index, Ma))
                }
            }
        }
    }
    Fa.exports = function(t) {
        var e;
        if (t.md.options.typographer)
            for (e = t.tokens.length - 1; e >= 0; e--) t.tokens[e].type !== "inline" || !Td.test(t.tokens[e].content) || $d(t.tokens[e].children, t)
    }
});
var Pa = _((nv, Ba) => {
    "use strict";
    Ba.exports = function(t) {
        var e, i, r, o, s, a, l = t.tokens;
        for (e = 0, i = l.length; e < i; e++)
            if (l[e].type === "inline") {
                for (r = l[e].children, s = r.length, o = 0; o < s; o++) r[o].type === "text_special" && (r[o].type = "text");
                for (o = a = 0; o < s; o++) r[o].type === "text" && o + 1 < s && r[o + 1].type === "text" ? r[o + 1].content = r[o].content + r[o + 1].content : (o !== a && (r[a] = r[o]), a++);
                o !== a && (r.length = a)
            }
    }
});
var di = _((iv, Oa) => {
    "use strict";

    function ve(n, t, e) {
        this.type = n, this.tag = t, this.attrs = null, this.map = null, this.nesting = e, this.level = 0, this.children = null, this.content = "", this.markup = "", this.info = "", this.meta = null, this.block = !1, this.hidden = !1
    }
    ve.prototype.attrIndex = function(t) {
        var e, i, r;
        if (!this.attrs) return -1;
        for (e = this.attrs, i = 0, r = e.length; i < r; i++)
            if (e[i][0] === t) return i;
        return -1
    };
    ve.prototype.attrPush = function(t) {
        this.attrs ? this.attrs.push(t) : this.attrs = [t]
    };
    ve.prototype.attrSet = function(t, e) {
        var i = this.attrIndex(t),
            r = [t, e];
        i < 0 ? this.attrPush(r) : this.attrs[i] = r
    };
    ve.prototype.attrGet = function(t) {
        var e = this.attrIndex(t),
            i = null;
        return e >= 0 && (i = this.attrs[e][1]), i
    };
    ve.prototype.attrJoin = function(t, e) {
        var i = this.attrIndex(t);
        i < 0 ? this.attrPush([t, e]) : this.attrs[i][1] = this.attrs[i][1] + " " + e
    };
    Oa.exports = ve
});
var za = _((rv, Na) => {
    "use strict";
    var Id = di();

    function Ra(n, t, e) {
        this.src = n, this.env = e, this.tokens = [], this.inlineMode = !1, this.md = t
    }
    Ra.prototype.Token = Id;
    Na.exports = Ra
});
var Ua = _((ov, Ha) => {
    "use strict";
    var Md = ui(),
        Yr = [
            ["normalize", wa()],
            ["block", xa()],
            ["inline", Ca()],
            ["linkify", _a()],
            ["replacements", Da()],
            ["smartquotes", qa()],
            ["text_join", Pa()]
        ];

    function Jr() {
        this.ruler = new Md;
        for (var n = 0; n < Yr.length; n++) this.ruler.push(Yr[n][0], Yr[n][1])
    }
    Jr.prototype.process = function(n) {
        var t, e, i;
        for (i = this.ruler.getRules(""), t = 0, e = i.length; t < e; t++) i[t](n)
    };
    Jr.prototype.State = za();
    Ha.exports = Jr
});
var Wa = _((sv, Va) => {
    "use strict";
    var Qr = N().isSpace;

    function to(n, t) {
        var e = n.bMarks[t] + n.tShift[t],
            i = n.eMarks[t];
        return n.src.slice(e, i)
    }

    function ja(n) {
        var t = [],
            e = 0,
            i = n.length,
            r, o = !1,
            s = 0,
            a = "";
        for (r = n.charCodeAt(e); e < i;) r === 124 && (o ? (a += n.substring(s, e - 1), s = e) : (t.push(a + n.substring(s, e)), a = "", s = e + 1)), o = r === 92, e++, r = n.charCodeAt(e);
        return t.push(a + n.substring(s)), t
    }
    Va.exports = function(t, e, i, r) {
        var o, s, a, l, c, u, h, d, f, p, m, w, v, b, k, x, E, y;
        if (e + 2 > i || (u = e + 1, t.sCount[u] < t.blkIndent) || t.sCount[u] - t.blkIndent >= 4 || (a = t.bMarks[u] + t.tShift[u], a >= t.eMarks[u]) || (E = t.src.charCodeAt(a++), E !== 124 && E !== 45 && E !== 58) || a >= t.eMarks[u] || (y = t.src.charCodeAt(a++), y !== 124 && y !== 45 && y !== 58 && !Qr(y)) || E === 45 && Qr(y)) return !1;
        for (; a < t.eMarks[u];) {
            if (o = t.src.charCodeAt(a), o !== 124 && o !== 45 && o !== 58 && !Qr(o)) return !1;
            a++
        }
        for (s = to(t, e + 1), h = s.split("|"), p = [], l = 0; l < h.length; l++) {
            if (m = h[l].trim(), !m) {
                if (l === 0 || l === h.length - 1) continue;
                return !1
            }
            if (!/^:?-+:?$/.test(m)) return !1;
            m.charCodeAt(m.length - 1) === 58 ? p.push(m.charCodeAt(0) === 58 ? "center" : "right") : m.charCodeAt(0) === 58 ? p.push("left") : p.push("")
        }
        if (s = to(t, e).trim(), s.indexOf("|") === -1 || t.sCount[e] - t.blkIndent >= 4 || (h = ja(s), h.length && h[0] === "" && h.shift(), h.length && h[h.length - 1] === "" && h.pop(), d = h.length, d === 0 || d !== p.length)) return !1;
        if (r) return !0;
        for (b = t.parentType, t.parentType = "table", x = t.md.block.ruler.getRules("blockquote"), f = t.push("table_open", "table", 1), f.map = w = [e, 0], f = t.push("thead_open", "thead", 1), f.map = [e, e + 1], f = t.push("tr_open", "tr", 1), f.map = [e, e + 1], l = 0; l < h.length; l++) f = t.push("th_open", "th", 1), p[l] && (f.attrs = [
            ["style", "text-align:" + p[l]]
        ]), f = t.push("inline", "", 0), f.content = h[l].trim(), f.children = [], f = t.push("th_close", "th", -1);
        for (f = t.push("tr_close", "tr", -1), f = t.push("thead_close", "thead", -1), u = e + 2; u < i && !(t.sCount[u] < t.blkIndent); u++) {
            for (k = !1, l = 0, c = x.length; l < c; l++)
                if (x[l](t, u, i, !0)) {
                    k = !0;
                    break
                } if (k || (s = to(t, u).trim(), !s) || t.sCount[u] - t.blkIndent >= 4) break;
            for (h = ja(s), h.length && h[0] === "" && h.shift(), h.length && h[h.length - 1] === "" && h.pop(), u === e + 2 && (f = t.push("tbody_open", "tbody", 1), f.map = v = [e + 2, 0]), f = t.push("tr_open", "tr", 1), f.map = [u, u + 1], l = 0; l < d; l++) f = t.push("td_open", "td", 1), p[l] && (f.attrs = [
                ["style", "text-align:" + p[l]]
            ]), f = t.push("inline", "", 0), f.content = h[l] ? h[l].trim() : "", f.children = [], f = t.push("td_close", "td", -1);
            f = t.push("tr_close", "tr", -1)
        }
        return v && (f = t.push("tbody_close", "tbody", -1), v[1] = u), f = t.push("table_close", "table", -1), w[1] = u, t.parentType = b, t.line = u, !0
    }
});
var Ka = _((av, Ga) => {
    "use strict";
    Ga.exports = function(t, e, i) {
        var r, o, s;
        if (t.sCount[e] - t.blkIndent < 4) return !1;
        for (o = r = e + 1; r < i;) {
            if (t.isEmpty(r)) {
                r++;
                continue
            }
            if (t.sCount[r] - t.blkIndent >= 4) {
                r++, o = r;
                continue
            }
            break
        }
        return t.line = o, s = t.push("code_block", "code", 0), s.content = t.getLines(e, o, 4 + t.blkIndent, !1) + `
`, s.map = [e, t.line], !0
    }
});
var Xa = _((lv, Za) => {
    "use strict";
    Za.exports = function(t, e, i, r) {
        var o, s, a, l, c, u, h, d = !1,
            f = t.bMarks[e] + t.tShift[e],
            p = t.eMarks[e];
        if (t.sCount[e] - t.blkIndent >= 4 || f + 3 > p || (o = t.src.charCodeAt(f), o !== 126 && o !== 96) || (c = f, f = t.skipChars(f, o), s = f - c, s < 3) || (h = t.src.slice(c, f), a = t.src.slice(f, p), o === 96 && a.indexOf(String.fromCharCode(o)) >= 0)) return !1;
        if (r) return !0;
        for (l = e; l++, !(l >= i || (f = c = t.bMarks[l] + t.tShift[l], p = t.eMarks[l], f < p && t.sCount[l] < t.blkIndent));)
            if (t.src.charCodeAt(f) === o && !(t.sCount[l] - t.blkIndent >= 4) && (f = t.skipChars(f, o), !(f - c < s) && (f = t.skipSpaces(f), !(f < p)))) {
                d = !0;
                break
            } return s = t.sCount[e], t.line = l + (d ? 1 : 0), u = t.push("fence", "code", 0), u.info = a, u.content = t.getLines(e + 1, l, s, !0), u.markup = h, u.map = [e, t.line], !0
    }
});
var Ja = _((cv, Ya) => {
    "use strict";
    var Fd = N().isSpace;
    Ya.exports = function(t, e, i, r) {
        var o, s, a, l, c, u, h, d, f, p, m, w, v, b, k, x, E, y, S, D, M = t.lineMax,
            T = t.bMarks[e] + t.tShift[e],
            P = t.eMarks[e];
        if (t.sCount[e] - t.blkIndent >= 4 || t.src.charCodeAt(T) !== 62) return !1;
        if (r) return !0;
        for (p = [], m = [], b = [], k = [], y = t.md.block.ruler.getRules("blockquote"), v = t.parentType, t.parentType = "blockquote", d = e; d < i && (D = t.sCount[d] < t.blkIndent, T = t.bMarks[d] + t.tShift[d], P = t.eMarks[d], !(T >= P)); d++) {
            if (t.src.charCodeAt(T++) === 62 && !D) {
                for (l = t.sCount[d] + 1, t.src.charCodeAt(T) === 32 ? (T++, l++, o = !1, x = !0) : t.src.charCodeAt(T) === 9 ? (x = !0, (t.bsCount[d] + l) % 4 === 3 ? (T++, l++, o = !1) : o = !0) : x = !1, f = l, p.push(t.bMarks[d]), t.bMarks[d] = T; T < P && (s = t.src.charCodeAt(T), Fd(s));) {
                    s === 9 ? f += 4 - (f + t.bsCount[d] + (o ? 1 : 0)) % 4 : f++;
                    T++
                }
                u = T >= P, m.push(t.bsCount[d]), t.bsCount[d] = t.sCount[d] + 1 + (x ? 1 : 0), b.push(t.sCount[d]), t.sCount[d] = f - l, k.push(t.tShift[d]), t.tShift[d] = T - t.bMarks[d];
                continue
            }
            if (u) break;
            for (E = !1, a = 0, c = y.length; a < c; a++)
                if (y[a](t, d, i, !0)) {
                    E = !0;
                    break
                } if (E) {
                t.lineMax = d, t.blkIndent !== 0 && (p.push(t.bMarks[d]), m.push(t.bsCount[d]), k.push(t.tShift[d]), b.push(t.sCount[d]), t.sCount[d] -= t.blkIndent);
                break
            }
            p.push(t.bMarks[d]), m.push(t.bsCount[d]), k.push(t.tShift[d]), b.push(t.sCount[d]), t.sCount[d] = -1
        }
        for (w = t.blkIndent, t.blkIndent = 0, S = t.push("blockquote_open", "blockquote", 1), S.markup = ">", S.map = h = [e, 0], t.md.block.tokenize(t, e, d), S = t.push("blockquote_close", "blockquote", -1), S.markup = ">", t.lineMax = M, t.parentType = v, h[1] = t.line, a = 0; a < k.length; a++) t.bMarks[a + e] = p[a], t.tShift[a + e] = k[a], t.sCount[a + e] = b[a], t.bsCount[a + e] = m[a];
        return t.blkIndent = w, !0
    }
});
var tl = _((uv, Qa) => {
    "use strict";
    var qd = N().isSpace;
    Qa.exports = function(t, e, i, r) {
        var o, s, a, l, c = t.bMarks[e] + t.tShift[e],
            u = t.eMarks[e];
        if (t.sCount[e] - t.blkIndent >= 4 || (o = t.src.charCodeAt(c++), o !== 42 && o !== 45 && o !== 95)) return !1;
        for (s = 1; c < u;) {
            if (a = t.src.charCodeAt(c++), a !== o && !qd(a)) return !1;
            a === o && s++
        }
        return s < 3 ? !1 : (r || (t.line = e + 1, l = t.push("hr", "hr", 0), l.map = [e, t.line], l.markup = Array(s + 1).join(String.fromCharCode(o))), !0)
    }
});
var ol = _((hv, rl) => {
    "use strict";
    var il = N().isSpace;

    function el(n, t) {
        var e, i, r, o;
        return i = n.bMarks[t] + n.tShift[t], r = n.eMarks[t], e = n.src.charCodeAt(i++), e !== 42 && e !== 45 && e !== 43 || i < r && (o = n.src.charCodeAt(i), !il(o)) ? -1 : i
    }

    function nl(n, t) {
        var e, i = n.bMarks[t] + n.tShift[t],
            r = i,
            o = n.eMarks[t];
        if (r + 1 >= o || (e = n.src.charCodeAt(r++), e < 48 || e > 57)) return -1;
        for (;;) {
            if (r >= o) return -1;
            if (e = n.src.charCodeAt(r++), e >= 48 && e <= 57) {
                if (r - i >= 10) return -1;
                continue
            }
            if (e === 41 || e === 46) break;
            return -1
        }
        return r < o && (e = n.src.charCodeAt(r), !il(e)) ? -1 : r
    }

    function Bd(n, t) {
        var e, i, r = n.level + 2;
        for (e = t + 2, i = n.tokens.length - 2; e < i; e++) n.tokens[e].level === r && n.tokens[e].type === "paragraph_open" && (n.tokens[e + 2].hidden = !0, n.tokens[e].hidden = !0, e += 2)
    }
    rl.exports = function(t, e, i, r) {
        var o, s, a, l, c, u, h, d, f, p, m, w, v, b, k, x, E, y, S, D, M, T, P, H, U, et, W, $ = e,
            Ot = !1,
            Rt = !0;
        if (t.sCount[$] - t.blkIndent >= 4 || t.listIndent >= 0 && t.sCount[$] - t.listIndent >= 4 && t.sCount[$] < t.blkIndent) return !1;
        if (r && t.parentType === "paragraph" && t.sCount[$] >= t.blkIndent && (Ot = !0), (T = nl(t, $)) >= 0) {
            if (h = !0, H = t.bMarks[$] + t.tShift[$], v = Number(t.src.slice(H, T - 1)), Ot && v !== 1) return !1
        } else if ((T = el(t, $)) >= 0) h = !1;
        else return !1;
        if (Ot && t.skipSpaces(T) >= t.eMarks[$]) return !1;
        if (r) return !0;
        for (w = t.src.charCodeAt(T - 1), m = t.tokens.length, h ? (W = t.push("ordered_list_open", "ol", 1), v !== 1 && (W.attrs = [
                ["start", v]
            ])) : W = t.push("bullet_list_open", "ul", 1), W.map = p = [$, 0], W.markup = String.fromCharCode(w), P = !1, et = t.md.block.ruler.getRules("list"), E = t.parentType, t.parentType = "list"; $ < i;) {
            for (M = T, b = t.eMarks[$], u = k = t.sCount[$] + T - (t.bMarks[$] + t.tShift[$]); M < b;) {
                if (o = t.src.charCodeAt(M), o === 9) k += 4 - (k + t.bsCount[$]) % 4;
                else if (o === 32) k++;
                else break;
                M++
            }
            if (s = M, s >= b ? c = 1 : c = k - u, c > 4 && (c = 1), l = u + c, W = t.push("list_item_open", "li", 1), W.markup = String.fromCharCode(w), W.map = d = [$, 0], h && (W.info = t.src.slice(H, T - 1)), D = t.tight, S = t.tShift[$], y = t.sCount[$], x = t.listIndent, t.listIndent = t.blkIndent, t.blkIndent = l, t.tight = !0, t.tShift[$] = s - t.bMarks[$], t.sCount[$] = k, s >= b && t.isEmpty($ + 1) ? t.line = Math.min(t.line + 2, i) : t.md.block.tokenize(t, $, i, !0), (!t.tight || P) && (Rt = !1), P = t.line - $ > 1 && t.isEmpty(t.line - 1), t.blkIndent = t.listIndent, t.listIndent = x, t.tShift[$] = S, t.sCount[$] = y, t.tight = D, W = t.push("list_item_close", "li", -1), W.markup = String.fromCharCode(w), $ = t.line, d[1] = $, $ >= i || t.sCount[$] < t.blkIndent || t.sCount[$] - t.blkIndent >= 4) break;
            for (U = !1, a = 0, f = et.length; a < f; a++)
                if (et[a](t, $, i, !0)) {
                    U = !0;
                    break
                } if (U) break;
            if (h) {
                if (T = nl(t, $), T < 0) break;
                H = t.bMarks[$] + t.tShift[$]
            } else if (T = el(t, $), T < 0) break;
            if (w !== t.src.charCodeAt(T - 1)) break
        }
        return h ? W = t.push("ordered_list_close", "ol", -1) : W = t.push("bullet_list_close", "ul", -1), W.markup = String.fromCharCode(w), p[1] = $, t.line = $, t.parentType = E, Rt && Bd(t, m), !0
    }
});
var al = _((dv, sl) => {
    "use strict";
    var Pd = N().normalizeReference,
        pi = N().isSpace;
    sl.exports = function(t, e, i, r) {
        var o, s, a, l, c, u, h, d, f, p, m, w, v, b, k, x, E = 0,
            y = t.bMarks[e] + t.tShift[e],
            S = t.eMarks[e],
            D = e + 1;
        if (t.sCount[e] - t.blkIndent >= 4 || t.src.charCodeAt(y) !== 91) return !1;
        for (; ++y < S;)
            if (t.src.charCodeAt(y) === 93 && t.src.charCodeAt(y - 1) !== 92) {
                if (y + 1 === S || t.src.charCodeAt(y + 1) !== 58) return !1;
                break
            } for (l = t.lineMax, k = t.md.block.ruler.getRules("reference"), p = t.parentType, t.parentType = "reference"; D < l && !t.isEmpty(D); D++)
            if (!(t.sCount[D] - t.blkIndent > 3) && !(t.sCount[D] < 0)) {
                for (b = !1, u = 0, h = k.length; u < h; u++)
                    if (k[u](t, D, l, !0)) {
                        b = !0;
                        break
                    } if (b) break
            } for (v = t.getLines(e, D, t.blkIndent, !1).trim(), S = v.length, y = 1; y < S; y++) {
            if (o = v.charCodeAt(y), o === 91) return !1;
            if (o === 93) {
                f = y;
                break
            } else o === 10 ? E++ : o === 92 && (y++, y < S && v.charCodeAt(y) === 10 && E++)
        }
        if (f < 0 || v.charCodeAt(f + 1) !== 58) return !1;
        for (y = f + 2; y < S; y++)
            if (o = v.charCodeAt(y), o === 10) E++;
            else if (!pi(o)) break;
        if (m = t.md.helpers.parseLinkDestination(v, y, S), !m.ok || (c = t.md.normalizeLink(m.str), !t.md.validateLink(c))) return !1;
        for (y = m.pos, E += m.lines, s = y, a = E, w = y; y < S; y++)
            if (o = v.charCodeAt(y), o === 10) E++;
            else if (!pi(o)) break;
        for (m = t.md.helpers.parseLinkTitle(v, y, S), y < S && w !== y && m.ok ? (x = m.str, y = m.pos, E += m.lines) : (x = "", y = s, E = a); y < S && (o = v.charCodeAt(y), !!pi(o));) y++;
        if (y < S && v.charCodeAt(y) !== 10 && x)
            for (x = "", y = s, E = a; y < S && (o = v.charCodeAt(y), !!pi(o));) y++;
        return y < S && v.charCodeAt(y) !== 10 || (d = Pd(v.slice(1, f)), !d) ? !1 : (r || (typeof t.env.references > "u" && (t.env.references = {}), typeof t.env.references[d] > "u" && (t.env.references[d] = {
            title: x,
            href: c
        }), t.parentType = p, t.line = e + E + 1), !0)
    }
});
var cl = _((pv, ll) => {
    "use strict";
    ll.exports = ["address", "article", "aside", "base", "basefont", "blockquote", "body", "caption", "center", "col", "colgroup", "dd", "details", "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hr", "html", "iframe", "legend", "li", "link", "main", "menu", "menuitem", "nav", "noframes", "ol", "optgroup", "option", "p", "param", "section", "source", "summary", "table", "tbody", "td", "tfoot", "th", "thead", "title", "tr", "track", "ul"]
});
var no = _((fv, eo) => {
    "use strict";
    var Od = "[a-zA-Z_:][a-zA-Z0-9:._-]*",
        Rd = "[^\"'=<>`\\x00-\\x20]+",
        Nd = "'[^']*'",
        zd = '"[^"]*"',
        Hd = "(?:" + Rd + "|" + Nd + "|" + zd + ")",
        Ud = "(?:\\s+" + Od + "(?:\\s*=\\s*" + Hd + ")?)",
        ul = "<[A-Za-z][A-Za-z0-9\\-]*" + Ud + "*\\s*\\/?>",
        hl = "<\\/[A-Za-z][A-Za-z0-9\\-]*\\s*>",
        jd = "<!---->|<!--(?:-?[^>-])(?:-?[^-])*-->",
        Vd = "<[?][\\s\\S]*?[?]>",
        Wd = "<![A-Z]+\\s+[^>]*>",
        Gd = "<!\\[CDATA\\[[\\s\\S]*?\\]\\]>",
        Kd = new RegExp("^(?:" + ul + "|" + hl + "|" + jd + "|" + Vd + "|" + Wd + "|" + Gd + ")"),
        Zd = new RegExp("^(?:" + ul + "|" + hl + ")");
    eo.exports.HTML_TAG_RE = Kd;
    eo.exports.HTML_OPEN_CLOSE_TAG_RE = Zd
});
var pl = _((mv, dl) => {
    "use strict";
    var Xd = cl(),
        Yd = no().HTML_OPEN_CLOSE_TAG_RE,
        we = [
            [/^<(script|pre|style|textarea)(?=(\s|>|$))/i, /<\/(script|pre|style|textarea)>/i, !0],
            [/^<!--/, /-->/, !0],
            [/^<\?/, /\?>/, !0],
            [/^<![A-Z]/, />/, !0],
            [/^<!\[CDATA\[/, /\]\]>/, !0],
            [new RegExp("^</?(" + Xd.join("|") + ")(?=(\\s|/?>|$))", "i"), /^$/, !0],
            [new RegExp(Yd.source + "\\s*$"), /^$/, !1]
        ];
    dl.exports = function(t, e, i, r) {
        var o, s, a, l, c = t.bMarks[e] + t.tShift[e],
            u = t.eMarks[e];
        if (t.sCount[e] - t.blkIndent >= 4 || !t.md.options.html || t.src.charCodeAt(c) !== 60) return !1;
        for (l = t.src.slice(c, u), o = 0; o < we.length && !we[o][0].test(l); o++);
        if (o === we.length) return !1;
        if (r) return we[o][2];
        if (s = e + 1, !we[o][1].test(l)) {
            for (; s < i && !(t.sCount[s] < t.blkIndent); s++)
                if (c = t.bMarks[s] + t.tShift[s], u = t.eMarks[s], l = t.src.slice(c, u), we[o][1].test(l)) {
                    l.length !== 0 && s++;
                    break
                }
        }
        return t.line = s, a = t.push("html_block", "", 0), a.map = [e, s], a.content = t.getLines(e, s, t.blkIndent, !0), !0
    }
});
var gl = _((gv, ml) => {
    "use strict";
    var fl = N().isSpace;
    ml.exports = function(t, e, i, r) {
        var o, s, a, l, c = t.bMarks[e] + t.tShift[e],
            u = t.eMarks[e];
        if (t.sCount[e] - t.blkIndent >= 4 || (o = t.src.charCodeAt(c), o !== 35 || c >= u)) return !1;
        for (s = 1, o = t.src.charCodeAt(++c); o === 35 && c < u && s <= 6;) s++, o = t.src.charCodeAt(++c);
        return s > 6 || c < u && !fl(o) ? !1 : (r || (u = t.skipSpacesBack(u, c), a = t.skipCharsBack(u, 35, c), a > c && fl(t.src.charCodeAt(a - 1)) && (u = a), t.line = e + 1, l = t.push("heading_open", "h" + String(s), 1), l.markup = "########".slice(0, s), l.map = [e, t.line], l = t.push("inline", "", 0), l.content = t.src.slice(c, u).trim(), l.map = [e, t.line], l.children = [], l = t.push("heading_close", "h" + String(s), -1), l.markup = "########".slice(0, s)), !0)
    }
});
var vl = _((bv, bl) => {
    "use strict";
    bl.exports = function(t, e, i) {
        var r, o, s, a, l, c, u, h, d, f = e + 1,
            p, m = t.md.block.ruler.getRules("paragraph");
        if (t.sCount[e] - t.blkIndent >= 4) return !1;
        for (p = t.parentType, t.parentType = "paragraph"; f < i && !t.isEmpty(f); f++)
            if (!(t.sCount[f] - t.blkIndent > 3)) {
                if (t.sCount[f] >= t.blkIndent && (c = t.bMarks[f] + t.tShift[f], u = t.eMarks[f], c < u && (d = t.src.charCodeAt(c), (d === 45 || d === 61) && (c = t.skipChars(c, d), c = t.skipSpaces(c), c >= u)))) {
                    h = d === 61 ? 1 : 2;
                    break
                }
                if (!(t.sCount[f] < 0)) {
                    for (o = !1, s = 0, a = m.length; s < a; s++)
                        if (m[s](t, f, i, !0)) {
                            o = !0;
                            break
                        } if (o) break
                }
            } return h ? (r = t.getLines(e, f, t.blkIndent, !1).trim(), t.line = f + 1, l = t.push("heading_open", "h" + String(h), 1), l.markup = String.fromCharCode(d), l.map = [e, t.line], l = t.push("inline", "", 0), l.content = r, l.map = [e, t.line - 1], l.children = [], l = t.push("heading_close", "h" + String(h), -1), l.markup = String.fromCharCode(d), t.parentType = p, !0) : !1
    }
});
var yl = _((vv, wl) => {
    "use strict";
    wl.exports = function(t, e, i) {
        var r, o, s, a, l, c, u = e + 1,
            h = t.md.block.ruler.getRules("paragraph");
        for (c = t.parentType, t.parentType = "paragraph"; u < i && !t.isEmpty(u); u++)
            if (!(t.sCount[u] - t.blkIndent > 3) && !(t.sCount[u] < 0)) {
                for (o = !1, s = 0, a = h.length; s < a; s++)
                    if (h[s](t, u, i, !0)) {
                        o = !0;
                        break
                    } if (o) break
            } return r = t.getLines(e, u, t.blkIndent, !1).trim(), t.line = u, l = t.push("paragraph_open", "p", 1), l.map = [e, t.line], l = t.push("inline", "", 0), l.content = r, l.map = [e, t.line], l.children = [], l = t.push("paragraph_close", "p", -1), t.parentType = c, !0
    }
});
var Cl = _((wv, kl) => {
    "use strict";
    var xl = di(),
        fi = N().isSpace;

    function Lt(n, t, e, i) {
        var r, o, s, a, l, c, u, h;
        for (this.src = n, this.md = t, this.env = e, this.tokens = i, this.bMarks = [], this.eMarks = [], this.tShift = [], this.sCount = [], this.bsCount = [], this.blkIndent = 0, this.line = 0, this.lineMax = 0, this.tight = !1, this.ddIndent = -1, this.listIndent = -1, this.parentType = "root", this.level = 0, this.result = "", o = this.src, h = !1, s = a = c = u = 0, l = o.length; a < l; a++) {
            if (r = o.charCodeAt(a), !h)
                if (fi(r)) {
                    c++, r === 9 ? u += 4 - u % 4 : u++;
                    continue
                } else h = !0;
            (r === 10 || a === l - 1) && (r !== 10 && a++, this.bMarks.push(s), this.eMarks.push(a), this.tShift.push(c), this.sCount.push(u), this.bsCount.push(0), h = !1, c = 0, u = 0, s = a + 1)
        }
        this.bMarks.push(o.length), this.eMarks.push(o.length), this.tShift.push(0), this.sCount.push(0), this.bsCount.push(0), this.lineMax = this.bMarks.length - 1
    }
    Lt.prototype.push = function(n, t, e) {
        var i = new xl(n, t, e);
        return i.block = !0, e < 0 && this.level--, i.level = this.level, e > 0 && this.level++, this.tokens.push(i), i
    };
    Lt.prototype.isEmpty = function(t) {
        return this.bMarks[t] + this.tShift[t] >= this.eMarks[t]
    };
    Lt.prototype.skipEmptyLines = function(t) {
        for (var e = this.lineMax; t < e && !(this.bMarks[t] + this.tShift[t] < this.eMarks[t]); t++);
        return t
    };
    Lt.prototype.skipSpaces = function(t) {
        for (var e, i = this.src.length; t < i && (e = this.src.charCodeAt(t), !!fi(e)); t++);
        return t
    };
    Lt.prototype.skipSpacesBack = function(t, e) {
        if (t <= e) return t;
        for (; t > e;)
            if (!fi(this.src.charCodeAt(--t))) return t + 1;
        return t
    };
    Lt.prototype.skipChars = function(t, e) {
        for (var i = this.src.length; t < i && this.src.charCodeAt(t) === e; t++);
        return t
    };
    Lt.prototype.skipCharsBack = function(t, e, i) {
        if (t <= i) return t;
        for (; t > i;)
            if (e !== this.src.charCodeAt(--t)) return t + 1;
        return t
    };
    Lt.prototype.getLines = function(t, e, i, r) {
        var o, s, a, l, c, u, h, d = t;
        if (t >= e) return "";
        for (u = new Array(e - t), o = 0; d < e; d++, o++) {
            for (s = 0, h = l = this.bMarks[d], d + 1 < e || r ? c = this.eMarks[d] + 1 : c = this.eMarks[d]; l < c && s < i;) {
                if (a = this.src.charCodeAt(l), fi(a)) a === 9 ? s += 4 - (s + this.bsCount[d]) % 4 : s++;
                else if (l - h < this.tShift[d]) s++;
                else break;
                l++
            }
            s > i ? u[o] = new Array(s - i + 1).join(" ") + this.src.slice(l, c) : u[o] = this.src.slice(l, c)
        }
        return u.join("")
    };
    Lt.prototype.Token = xl;
    kl.exports = Lt
});
var _l = _((yv, El) => {
    "use strict";
    var Jd = ui(),
        mi = [
            ["table", Wa(), ["paragraph", "reference"]],
            ["code", Ka()],
            ["fence", Xa(), ["paragraph", "reference", "blockquote", "list"]],
            ["blockquote", Ja(), ["paragraph", "reference", "blockquote", "list"]],
            ["hr", tl(), ["paragraph", "reference", "blockquote", "list"]],
            ["list", ol(), ["paragraph", "reference", "blockquote"]],
            ["reference", al()],
            ["html_block", pl(), ["paragraph", "reference", "blockquote"]],
            ["heading", gl(), ["paragraph", "reference", "blockquote"]],
            ["lheading", vl()],
            ["paragraph", yl()]
        ];

    function gi() {
        this.ruler = new Jd;
        for (var n = 0; n < mi.length; n++) this.ruler.push(mi[n][0], mi[n][1], {
            alt: (mi[n][2] || []).slice()
        })
    }
    gi.prototype.tokenize = function(n, t, e) {
        for (var i, r, o, s = this.ruler.getRules(""), a = s.length, l = t, c = !1, u = n.md.options.maxNesting; l < e && (n.line = l = n.skipEmptyLines(l), !(l >= e || n.sCount[l] < n.blkIndent));) {
            if (n.level >= u) {
                n.line = e;
                break
            }
            for (o = n.line, r = 0; r < a; r++)
                if (i = s[r](n, l, e, !1), i) {
                    if (o >= n.line) throw new Error("block rule didn't increment state.line");
                    break
                } if (!i) throw new Error("none of the block rules matched");
            n.tight = !c, n.isEmpty(n.line - 1) && (c = !0), l = n.line, l < e && n.isEmpty(l) && (c = !0, l++, n.line = l)
        }
    };
    gi.prototype.parse = function(n, t, e, i) {
        var r;
        n && (r = new this.State(n, t, e, i), this.tokenize(r, r.line, r.lineMax))
    };
    gi.prototype.State = Cl();
    El.exports = gi
});
var Al = _((xv, Sl) => {
    "use strict";

    function Qd(n) {
        switch (n) {
            case 10:
            case 33:
            case 35:
            case 36:
            case 37:
            case 38:
            case 42:
            case 43:
            case 45:
            case 58:
            case 60:
            case 61:
            case 62:
            case 64:
            case 91:
            case 92:
            case 93:
            case 94:
            case 95:
            case 96:
            case 123:
            case 125:
            case 126:
                return !0;
            default:
                return !1
        }
    }
    Sl.exports = function(t, e) {
        for (var i = t.pos; i < t.posMax && !Qd(t.src.charCodeAt(i));) i++;
        return i === t.pos ? !1 : (e || (t.pending += t.src.slice(t.pos, i)), t.pos = i, !0)
    }
});
var Ll = _((kv, Dl) => {
    "use strict";
    var tp = /(?:^|[^a-z0-9.+-])([a-z][a-z0-9.+-]*)$/i;
    Dl.exports = function(t, e) {
        var i, r, o, s, a, l, c, u;
        return !t.md.options.linkify || t.linkLevel > 0 || (i = t.pos, r = t.posMax, i + 3 > r) || t.src.charCodeAt(i) !== 58 || t.src.charCodeAt(i + 1) !== 47 || t.src.charCodeAt(i + 2) !== 47 || (o = t.pending.match(tp), !o) || (s = o[1], a = t.md.linkify.matchAtStart(t.src.slice(i - s.length)), !a) || (l = a.url, l.length <= s.length) || (l = l.replace(/\*+$/, ""), c = t.md.normalizeLink(l), !t.md.validateLink(c)) ? !1 : (e || (t.pending = t.pending.slice(0, -s.length), u = t.push("link_open", "a", 1), u.attrs = [
            ["href", c]
        ], u.markup = "linkify", u.info = "auto", u = t.push("text", "", 0), u.content = t.md.normalizeLinkText(l), u = t.push("link_close", "a", -1), u.markup = "linkify", u.info = "auto"), t.pos += l.length - s.length, !0)
    }
});
var $l = _((Cv, Tl) => {
    "use strict";
    var ep = N().isSpace;
    Tl.exports = function(t, e) {
        var i, r, o, s = t.pos;
        if (t.src.charCodeAt(s) !== 10) return !1;
        if (i = t.pending.length - 1, r = t.posMax, !e)
            if (i >= 0 && t.pending.charCodeAt(i) === 32)
                if (i >= 1 && t.pending.charCodeAt(i - 1) === 32) {
                    for (o = i - 1; o >= 1 && t.pending.charCodeAt(o - 1) === 32;) o--;
                    t.pending = t.pending.slice(0, o), t.push("hardbreak", "br", 0)
                } else t.pending = t.pending.slice(0, -1), t.push("softbreak", "br", 0);
        else t.push("softbreak", "br", 0);
        for (s++; s < r && ep(t.src.charCodeAt(s));) s++;
        return t.pos = s, !0
    }
});
var Ml = _((Ev, Il) => {
    "use strict";
    var np = N().isSpace,
        ro = [];
    for (io = 0; io < 256; io++) ro.push(0);
    var io;
    "\\!\"#$%&'()*+,./:;<=>?@[]^_`{|}~-".split("").forEach(function(n) {
        ro[n.charCodeAt(0)] = 1
    });
    Il.exports = function(t, e) {
        var i, r, o, s, a, l = t.pos,
            c = t.posMax;
        if (t.src.charCodeAt(l) !== 92 || (l++, l >= c)) return !1;
        if (i = t.src.charCodeAt(l), i === 10) {
            for (e || t.push("hardbreak", "br", 0), l++; l < c && (i = t.src.charCodeAt(l), !!np(i));) l++;
            return t.pos = l, !0
        }
        return s = t.src[l], i >= 55296 && i <= 56319 && l + 1 < c && (r = t.src.charCodeAt(l + 1), r >= 56320 && r <= 57343 && (s += t.src[l + 1], l++)), o = "\\" + s, e || (a = t.push("text_special", "", 0), i < 256 && ro[i] !== 0 ? a.content = s : a.content = o, a.markup = o, a.info = "escape"), t.pos = l + 1, !0
    }
});
var ql = _((_v, Fl) => {
    "use strict";
    Fl.exports = function(t, e) {
        var i, r, o, s, a, l, c, u, h = t.pos,
            d = t.src.charCodeAt(h);
        if (d !== 96) return !1;
        for (i = h, h++, r = t.posMax; h < r && t.src.charCodeAt(h) === 96;) h++;
        if (o = t.src.slice(i, h), c = o.length, t.backticksScanned && (t.backticks[c] || 0) <= i) return e || (t.pending += o), t.pos += c, !0;
        for (l = h;
            (a = t.src.indexOf("`", l)) !== -1;) {
            for (l = a + 1; l < r && t.src.charCodeAt(l) === 96;) l++;
            if (u = l - a, u === c) return e || (s = t.push("code_inline", "code", 0), s.markup = o, s.content = t.src.slice(h, a).replace(/\n/g, " ").replace(/^ (.+) $/, "$1")), t.pos = l, !0;
            t.backticks[u] = a
        }
        return t.backticksScanned = !0, e || (t.pending += o), t.pos += c, !0
    }
});
var so = _((Sv, oo) => {
    "use strict";
    oo.exports.tokenize = function(t, e) {
        var i, r, o, s, a, l = t.pos,
            c = t.src.charCodeAt(l);
        if (e || c !== 126 || (r = t.scanDelims(t.pos, !0), s = r.length, a = String.fromCharCode(c), s < 2)) return !1;
        for (s % 2 && (o = t.push("text", "", 0), o.content = a, s--), i = 0; i < s; i += 2) o = t.push("text", "", 0), o.content = a + a, t.delimiters.push({
            marker: c,
            length: 0,
            token: t.tokens.length - 1,
            end: -1,
            open: r.can_open,
            close: r.can_close
        });
        return t.pos += r.length, !0
    };

    function Bl(n, t) {
        var e, i, r, o, s, a = [],
            l = t.length;
        for (e = 0; e < l; e++) r = t[e], r.marker === 126 && r.end !== -1 && (o = t[r.end], s = n.tokens[r.token], s.type = "s_open", s.tag = "s", s.nesting = 1, s.markup = "~~", s.content = "", s = n.tokens[o.token], s.type = "s_close", s.tag = "s", s.nesting = -1, s.markup = "~~", s.content = "", n.tokens[o.token - 1].type === "text" && n.tokens[o.token - 1].content === "~" && a.push(o.token - 1));
        for (; a.length;) {
            for (e = a.pop(), i = e + 1; i < n.tokens.length && n.tokens[i].type === "s_close";) i++;
            i--, e !== i && (s = n.tokens[i], n.tokens[i] = n.tokens[e], n.tokens[e] = s)
        }
    }
    oo.exports.postProcess = function(t) {
        var e, i = t.tokens_meta,
            r = t.tokens_meta.length;
        for (Bl(t, t.delimiters), e = 0; e < r; e++) i[e] && i[e].delimiters && Bl(t, i[e].delimiters)
    }
});
var lo = _((Av, ao) => {
    "use strict";
    ao.exports.tokenize = function(t, e) {
        var i, r, o, s = t.pos,
            a = t.src.charCodeAt(s);
        if (e || a !== 95 && a !== 42) return !1;
        for (r = t.scanDelims(t.pos, a === 42), i = 0; i < r.length; i++) o = t.push("text", "", 0), o.content = String.fromCharCode(a), t.delimiters.push({
            marker: a,
            length: r.length,
            token: t.tokens.length - 1,
            end: -1,
            open: r.can_open,
            close: r.can_close
        });
        return t.pos += r.length, !0
    };

    function Pl(n, t) {
        var e, i, r, o, s, a, l = t.length;
        for (e = l - 1; e >= 0; e--) i = t[e], !(i.marker !== 95 && i.marker !== 42) && i.end !== -1 && (r = t[i.end], a = e > 0 && t[e - 1].end === i.end + 1 && t[e - 1].marker === i.marker && t[e - 1].token === i.token - 1 && t[i.end + 1].token === r.token + 1, s = String.fromCharCode(i.marker), o = n.tokens[i.token], o.type = a ? "strong_open" : "em_open", o.tag = a ? "strong" : "em", o.nesting = 1, o.markup = a ? s + s : s, o.content = "", o = n.tokens[r.token], o.type = a ? "strong_close" : "em_close", o.tag = a ? "strong" : "em", o.nesting = -1, o.markup = a ? s + s : s, o.content = "", a && (n.tokens[t[e - 1].token].content = "", n.tokens[t[i.end + 1].token].content = "", e--))
    }
    ao.exports.postProcess = function(t) {
        var e, i = t.tokens_meta,
            r = t.tokens_meta.length;
        for (Pl(t, t.delimiters), e = 0; e < r; e++) i[e] && i[e].delimiters && Pl(t, i[e].delimiters)
    }
});
var Rl = _((Dv, Ol) => {
    "use strict";
    var ip = N().normalizeReference,
        co = N().isSpace;
    Ol.exports = function(t, e) {
        var i, r, o, s, a, l, c, u, h, d = "",
            f = "",
            p = t.pos,
            m = t.posMax,
            w = t.pos,
            v = !0;
        if (t.src.charCodeAt(t.pos) !== 91 || (a = t.pos + 1, s = t.md.helpers.parseLinkLabel(t, t.pos, !0), s < 0)) return !1;
        if (l = s + 1, l < m && t.src.charCodeAt(l) === 40) {
            for (v = !1, l++; l < m && (r = t.src.charCodeAt(l), !(!co(r) && r !== 10)); l++);
            if (l >= m) return !1;
            if (w = l, c = t.md.helpers.parseLinkDestination(t.src, l, t.posMax), c.ok) {
                for (d = t.md.normalizeLink(c.str), t.md.validateLink(d) ? l = c.pos : d = "", w = l; l < m && (r = t.src.charCodeAt(l), !(!co(r) && r !== 10)); l++);
                if (c = t.md.helpers.parseLinkTitle(t.src, l, t.posMax), l < m && w !== l && c.ok)
                    for (f = c.str, l = c.pos; l < m && (r = t.src.charCodeAt(l), !(!co(r) && r !== 10)); l++);
            }(l >= m || t.src.charCodeAt(l) !== 41) && (v = !0), l++
        }
        if (v) {
            if (typeof t.env.references > "u") return !1;
            if (l < m && t.src.charCodeAt(l) === 91 ? (w = l + 1, l = t.md.helpers.parseLinkLabel(t, l), l >= 0 ? o = t.src.slice(w, l++) : l = s + 1) : l = s + 1, o || (o = t.src.slice(a, s)), u = t.env.references[ip(o)], !u) return t.pos = p, !1;
            d = u.href, f = u.title
        }
        return e || (t.pos = a, t.posMax = s, h = t.push("link_open", "a", 1), h.attrs = i = [
            ["href", d]
        ], f && i.push(["title", f]), t.linkLevel++, t.md.inline.tokenize(t), t.linkLevel--, h = t.push("link_close", "a", -1)), t.pos = l, t.posMax = m, !0
    }
});
var zl = _((Lv, Nl) => {
    "use strict";
    var rp = N().normalizeReference,
        uo = N().isSpace;
    Nl.exports = function(t, e) {
        var i, r, o, s, a, l, c, u, h, d, f, p, m, w = "",
            v = t.pos,
            b = t.posMax;
        if (t.src.charCodeAt(t.pos) !== 33 || t.src.charCodeAt(t.pos + 1) !== 91 || (l = t.pos + 2, a = t.md.helpers.parseLinkLabel(t, t.pos + 1, !1), a < 0)) return !1;
        if (c = a + 1, c < b && t.src.charCodeAt(c) === 40) {
            for (c++; c < b && (r = t.src.charCodeAt(c), !(!uo(r) && r !== 10)); c++);
            if (c >= b) return !1;
            for (m = c, h = t.md.helpers.parseLinkDestination(t.src, c, t.posMax), h.ok && (w = t.md.normalizeLink(h.str), t.md.validateLink(w) ? c = h.pos : w = ""), m = c; c < b && (r = t.src.charCodeAt(c), !(!uo(r) && r !== 10)); c++);
            if (h = t.md.helpers.parseLinkTitle(t.src, c, t.posMax), c < b && m !== c && h.ok)
                for (d = h.str, c = h.pos; c < b && (r = t.src.charCodeAt(c), !(!uo(r) && r !== 10)); c++);
            else d = "";
            if (c >= b || t.src.charCodeAt(c) !== 41) return t.pos = v, !1;
            c++
        } else {
            if (typeof t.env.references > "u") return !1;
            if (c < b && t.src.charCodeAt(c) === 91 ? (m = c + 1, c = t.md.helpers.parseLinkLabel(t, c), c >= 0 ? s = t.src.slice(m, c++) : c = a + 1) : c = a + 1, s || (s = t.src.slice(l, a)), u = t.env.references[rp(s)], !u) return t.pos = v, !1;
            w = u.href, d = u.title
        }
        return e || (o = t.src.slice(l, a), t.md.inline.parse(o, t.md, t.env, p = []), f = t.push("image", "img", 0), f.attrs = i = [
            ["src", w],
            ["alt", ""]
        ], f.children = p, f.content = o, d && i.push(["title", d])), t.pos = c, t.posMax = b, !0
    }
});
var Ul = _((Tv, Hl) => {
    "use strict";
    var op = /^([a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$/,
        sp = /^([a-zA-Z][a-zA-Z0-9+.\-]{1,31}):([^<>\x00-\x20]*)$/;
    Hl.exports = function(t, e) {
        var i, r, o, s, a, l, c = t.pos;
        if (t.src.charCodeAt(c) !== 60) return !1;
        for (a = t.pos, l = t.posMax;;) {
            if (++c >= l || (s = t.src.charCodeAt(c), s === 60)) return !1;
            if (s === 62) break
        }
        return i = t.src.slice(a + 1, c), sp.test(i) ? (r = t.md.normalizeLink(i), t.md.validateLink(r) ? (e || (o = t.push("link_open", "a", 1), o.attrs = [
            ["href", r]
        ], o.markup = "autolink", o.info = "auto", o = t.push("text", "", 0), o.content = t.md.normalizeLinkText(i), o = t.push("link_close", "a", -1), o.markup = "autolink", o.info = "auto"), t.pos += i.length + 2, !0) : !1) : op.test(i) ? (r = t.md.normalizeLink("mailto:" + i), t.md.validateLink(r) ? (e || (o = t.push("link_open", "a", 1), o.attrs = [
            ["href", r]
        ], o.markup = "autolink", o.info = "auto", o = t.push("text", "", 0), o.content = t.md.normalizeLinkText(i), o = t.push("link_close", "a", -1), o.markup = "autolink", o.info = "auto"), t.pos += i.length + 2, !0) : !1) : !1
    }
});
var Vl = _(($v, jl) => {
    "use strict";
    var ap = no().HTML_TAG_RE;

    function lp(n) {
        return /^<a[>\s]/i.test(n)
    }

    function cp(n) {
        return /^<\/a\s*>/i.test(n)
    }

    function up(n) {
        var t = n | 32;
        return t >= 97 && t <= 122
    }
    jl.exports = function(t, e) {
        var i, r, o, s, a = t.pos;
        return !t.md.options.html || (o = t.posMax, t.src.charCodeAt(a) !== 60 || a + 2 >= o) || (i = t.src.charCodeAt(a + 1), i !== 33 && i !== 63 && i !== 47 && !up(i)) || (r = t.src.slice(a).match(ap), !r) ? !1 : (e || (s = t.push("html_inline", "", 0), s.content = r[0], lp(s.content) && t.linkLevel++, cp(s.content) && t.linkLevel--), t.pos += r[0].length, !0)
    }
});
var Zl = _((Iv, Kl) => {
    "use strict";
    var Wl = Wr(),
        hp = N().has,
        dp = N().isValidEntityCode,
        Gl = N().fromCodePoint,
        pp = /^&#((?:x[a-f0-9]{1,6}|[0-9]{1,7}));/i,
        fp = /^&([a-z][a-z0-9]{1,31});/i;
    Kl.exports = function(t, e) {
        var i, r, o, s, a = t.pos,
            l = t.posMax;
        if (t.src.charCodeAt(a) !== 38 || a + 1 >= l) return !1;
        if (i = t.src.charCodeAt(a + 1), i === 35) {
            if (o = t.src.slice(a).match(pp), o) return e || (r = o[1][0].toLowerCase() === "x" ? parseInt(o[1].slice(1), 16) : parseInt(o[1], 10), s = t.push("text_special", "", 0), s.content = dp(r) ? Gl(r) : Gl(65533), s.markup = o[0], s.info = "entity"), t.pos += o[0].length, !0
        } else if (o = t.src.slice(a).match(fp), o && hp(Wl, o[1])) return e || (s = t.push("text_special", "", 0), s.content = Wl[o[1]], s.markup = o[0], s.info = "entity"), t.pos += o[0].length, !0;
        return !1
    }
});
var Jl = _((Mv, Yl) => {
    "use strict";

    function Xl(n) {
        var t, e, i, r, o, s, a, l, c = {},
            u = n.length;
        if (u) {
            var h = 0,
                d = -2,
                f = [];
            for (t = 0; t < u; t++)
                if (i = n[t], f.push(0), (n[h].marker !== i.marker || d !== i.token - 1) && (h = t), d = i.token, i.length = i.length || 0, !!i.close) {
                    for (c.hasOwnProperty(i.marker) || (c[i.marker] = [-1, -1, -1, -1, -1, -1]), o = c[i.marker][(i.open ? 3 : 0) + i.length % 3], e = h - f[h] - 1, s = e; e > o; e -= f[e] + 1)
                        if (r = n[e], r.marker === i.marker && r.open && r.end < 0 && (a = !1, (r.close || i.open) && (r.length + i.length) % 3 === 0 && (r.length % 3 !== 0 || i.length % 3 !== 0) && (a = !0), !a)) {
                            l = e > 0 && !n[e - 1].open ? f[e - 1] + 1 : 0, f[t] = t - e + l, f[e] = l, i.open = !1, r.end = t, r.close = !1, s = -1, d = -2;
                            break
                        } s !== -1 && (c[i.marker][(i.open ? 3 : 0) + (i.length || 0) % 3] = s)
                }
        }
    }
    Yl.exports = function(t) {
        var e, i = t.tokens_meta,
            r = t.tokens_meta.length;
        for (Xl(t.delimiters), e = 0; e < r; e++) i[e] && i[e].delimiters && Xl(i[e].delimiters)
    }
});
var tc = _((Fv, Ql) => {
    "use strict";
    Ql.exports = function(t) {
        var e, i, r = 0,
            o = t.tokens,
            s = t.tokens.length;
        for (e = i = 0; e < s; e++) o[e].nesting < 0 && r--, o[e].level = r, o[e].nesting > 0 && r++, o[e].type === "text" && e + 1 < s && o[e + 1].type === "text" ? o[e + 1].content = o[e].content + o[e + 1].content : (e !== i && (o[i] = o[e]), i++);
        e !== i && (o.length = i)
    }
});
var oc = _((qv, rc) => {
    "use strict";
    var ho = di(),
        ec = N().isWhiteSpace,
        nc = N().isPunctChar,
        ic = N().isMdAsciiPunct;

    function Ze(n, t, e, i) {
        this.src = n, this.env = e, this.md = t, this.tokens = i, this.tokens_meta = Array(i.length), this.pos = 0, this.posMax = this.src.length, this.level = 0, this.pending = "", this.pendingLevel = 0, this.cache = {}, this.delimiters = [], this._prev_delimiters = [], this.backticks = {}, this.backticksScanned = !1, this.linkLevel = 0
    }
    Ze.prototype.pushPending = function() {
        var n = new ho("text", "", 0);
        return n.content = this.pending, n.level = this.pendingLevel, this.tokens.push(n), this.pending = "", n
    };
    Ze.prototype.push = function(n, t, e) {
        this.pending && this.pushPending();
        var i = new ho(n, t, e),
            r = null;
        return e < 0 && (this.level--, this.delimiters = this._prev_delimiters.pop()), i.level = this.level, e > 0 && (this.level++, this._prev_delimiters.push(this.delimiters), this.delimiters = [], r = {
            delimiters: this.delimiters
        }), this.pendingLevel = this.level, this.tokens.push(i), this.tokens_meta.push(r), i
    };
    Ze.prototype.scanDelims = function(n, t) {
        var e = n,
            i, r, o, s, a, l, c, u, h, d = !0,
            f = !0,
            p = this.posMax,
            m = this.src.charCodeAt(n);
        for (i = n > 0 ? this.src.charCodeAt(n - 1) : 32; e < p && this.src.charCodeAt(e) === m;) e++;
        return o = e - n, r = e < p ? this.src.charCodeAt(e) : 32, c = ic(i) || nc(String.fromCharCode(i)), h = ic(r) || nc(String.fromCharCode(r)), l = ec(i), u = ec(r), u ? d = !1 : h && (l || c || (d = !1)), l ? f = !1 : c && (u || h || (f = !1)), t ? (s = d, a = f) : (s = d && (!f || c), a = f && (!d || h)), {
            can_open: s,
            can_close: a,
            length: o
        }
    };
    Ze.prototype.Token = ho;
    rc.exports = Ze
});
var lc = _((Bv, ac) => {
    "use strict";
    var sc = ui(),
        po = [
            ["text", Al()],
            ["linkify", Ll()],
            ["newline", $l()],
            ["escape", Ml()],
            ["backticks", ql()],
            ["strikethrough", so().tokenize],
            ["emphasis", lo().tokenize],
            ["link", Rl()],
            ["image", zl()],
            ["autolink", Ul()],
            ["html_inline", Vl()],
            ["entity", Zl()]
        ],
        fo = [
            ["balance_pairs", Jl()],
            ["strikethrough", so().postProcess],
            ["emphasis", lo().postProcess],
            ["fragments_join", tc()]
        ];

    function Xe() {
        var n;
        for (this.ruler = new sc, n = 0; n < po.length; n++) this.ruler.push(po[n][0], po[n][1]);
        for (this.ruler2 = new sc, n = 0; n < fo.length; n++) this.ruler2.push(fo[n][0], fo[n][1])
    }
    Xe.prototype.skipToken = function(n) {
        var t, e, i = n.pos,
            r = this.ruler.getRules(""),
            o = r.length,
            s = n.md.options.maxNesting,
            a = n.cache;
        if (typeof a[i] < "u") {
            n.pos = a[i];
            return
        }
        if (n.level < s) {
            for (e = 0; e < o; e++)
                if (n.level++, t = r[e](n, !0), n.level--, t) {
                    if (i >= n.pos) throw new Error("inline rule didn't increment state.pos");
                    break
                }
        } else n.pos = n.posMax;
        t || n.pos++, a[i] = n.pos
    };
    Xe.prototype.tokenize = function(n) {
        for (var t, e, i, r = this.ruler.getRules(""), o = r.length, s = n.posMax, a = n.md.options.maxNesting; n.pos < s;) {
            if (i = n.pos, n.level < a) {
                for (e = 0; e < o; e++)
                    if (t = r[e](n, !1), t) {
                        if (i >= n.pos) throw new Error("inline rule didn't increment state.pos");
                        break
                    }
            }
            if (t) {
                if (n.pos >= s) break;
                continue
            }
            n.pending += n.src[n.pos++]
        }
        n.pending && n.pushPending()
    };
    Xe.prototype.parse = function(n, t, e, i) {
        var r, o, s, a = new this.State(n, t, e, i);
        for (this.tokenize(a), o = this.ruler2.getRules(""), s = o.length, r = 0; r < s; r++) o[r](a)
    };
    Xe.prototype.State = oc();
    ac.exports = Xe
});
var uc = _((Pv, cc) => {
    "use strict";
    cc.exports = function(n) {
        var t = {};
        n = n || {}, t.src_Any = Kr().source, t.src_Cc = Zr().source, t.src_Z = Xr().source, t.src_P = oi().source, t.src_ZPCc = [t.src_Z, t.src_P, t.src_Cc].join("|"), t.src_ZCc = [t.src_Z, t.src_Cc].join("|");
        var e = "[><\uFF5C]";
        return t.src_pseudo_letter = "(?:(?!" + e + "|" + t.src_ZPCc + ")" + t.src_Any + ")", t.src_ip4 = "(?:(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", t.src_auth = "(?:(?:(?!" + t.src_ZCc + "|[@/\\[\\]()]).)+@)?", t.src_port = "(?::(?:6(?:[0-4]\\d{3}|5(?:[0-4]\\d{2}|5(?:[0-2]\\d|3[0-5])))|[1-5]?\\d{1,4}))?", t.src_host_terminator = "(?=$|" + e + "|" + t.src_ZPCc + ")(?!" + (n["---"] ? "-(?!--)|" : "-|") + "_|:\\d|\\.-|\\.(?!$|" + t.src_ZPCc + "))", t.src_path = "(?:[/?#](?:(?!" + t.src_ZCc + "|" + e + `|[()[\\]{}.,"'?!\\-;]).|\\[(?:(?!` + t.src_ZCc + "|\\]).)*\\]|\\((?:(?!" + t.src_ZCc + "|[)]).)*\\)|\\{(?:(?!" + t.src_ZCc + '|[}]).)*\\}|\\"(?:(?!' + t.src_ZCc + `|["]).)+\\"|\\'(?:(?!` + t.src_ZCc + "|[']).)+\\'|\\'(?=" + t.src_pseudo_letter + "|[-])|\\.{2,}[a-zA-Z0-9%/&]|\\.(?!" + t.src_ZCc + "|[.]|$)|" + (n["---"] ? "\\-(?!--(?:[^-]|$))(?:-*)|" : "\\-+|") + ",(?!" + t.src_ZCc + "|$)|;(?!" + t.src_ZCc + "|$)|\\!+(?!" + t.src_ZCc + "|[!]|$)|\\?(?!" + t.src_ZCc + "|[?]|$))+|\\/)?", t.src_email_name = '[\\-;:&=\\+\\$,\\.a-zA-Z0-9_][\\-;:&=\\+\\$,\\"\\.a-zA-Z0-9_]*', t.src_xn = "xn--[a-z0-9\\-]{1,59}", t.src_domain_root = "(?:" + t.src_xn + "|" + t.src_pseudo_letter + "{1,63})", t.src_domain = "(?:" + t.src_xn + "|(?:" + t.src_pseudo_letter + ")|(?:" + t.src_pseudo_letter + "(?:-|" + t.src_pseudo_letter + "){0,61}" + t.src_pseudo_letter + "))", t.src_host = "(?:(?:(?:(?:" + t.src_domain + ")\\.)*" + t.src_domain + "))", t.tpl_host_fuzzy = "(?:" + t.src_ip4 + "|(?:(?:(?:" + t.src_domain + ")\\.)+(?:%TLDS%)))", t.tpl_host_no_ip_fuzzy = "(?:(?:(?:" + t.src_domain + ")\\.)+(?:%TLDS%))", t.src_host_strict = t.src_host + t.src_host_terminator, t.tpl_host_fuzzy_strict = t.tpl_host_fuzzy + t.src_host_terminator, t.src_host_port_strict = t.src_host + t.src_port + t.src_host_terminator, t.tpl_host_port_fuzzy_strict = t.tpl_host_fuzzy + t.src_port + t.src_host_terminator, t.tpl_host_port_no_ip_fuzzy_strict = t.tpl_host_no_ip_fuzzy + t.src_port + t.src_host_terminator, t.tpl_host_fuzzy_test = "localhost|www\\.|\\.\\d{1,3}\\.|(?:\\.(?:%TLDS%)(?:" + t.src_ZPCc + "|>|$))", t.tpl_email_fuzzy = "(^|" + e + '|"|\\(|' + t.src_ZCc + ")(" + t.src_email_name + "@" + t.tpl_host_fuzzy_strict + ")", t.tpl_link_fuzzy = "(^|(?![.:/\\-_@])(?:[$+<=>^`|\uFF5C]|" + t.src_ZPCc + "))((?![$+<=>^`|\uFF5C])" + t.tpl_host_port_fuzzy_strict + t.src_path + ")", t.tpl_link_no_ip_fuzzy = "(^|(?![.:/\\-_@])(?:[$+<=>^`|\uFF5C]|" + t.src_ZPCc + "))((?![$+<=>^`|\uFF5C])" + t.tpl_host_port_no_ip_fuzzy_strict + t.src_path + ")", t
    }
});
var mc = _((Ov, fc) => {
    "use strict";

    function mo(n) {
        var t = Array.prototype.slice.call(arguments, 1);
        return t.forEach(function(e) {
            e && Object.keys(e).forEach(function(i) {
                n[i] = e[i]
            })
        }), n
    }

    function vi(n) {
        return Object.prototype.toString.call(n)
    }

    function mp(n) {
        return vi(n) === "[object String]"
    }

    function gp(n) {
        return vi(n) === "[object Object]"
    }

    function bp(n) {
        return vi(n) === "[object RegExp]"
    }

    function hc(n) {
        return vi(n) === "[object Function]"
    }

    function vp(n) {
        return n.replace(/[.?*+^$[\]\\(){}|-]/g, "\\$&")
    }
    var pc = {
        fuzzyLink: !0,
        fuzzyEmail: !0,
        fuzzyIP: !1
    };

    function wp(n) {
        return Object.keys(n || {}).reduce(function(t, e) {
            return t || pc.hasOwnProperty(e)
        }, !1)
    }
    var yp = {
            "http:": {
                validate: function(n, t, e) {
                    var i = n.slice(t);
                    return e.re.http || (e.re.http = new RegExp("^\\/\\/" + e.re.src_auth + e.re.src_host_port_strict + e.re.src_path, "i")), e.re.http.test(i) ? i.match(e.re.http)[0].length : 0
                }
            },
            "https:": "http:",
            "ftp:": "http:",
            "//": {
                validate: function(n, t, e) {
                    var i = n.slice(t);
                    return e.re.no_http || (e.re.no_http = new RegExp("^" + e.re.src_auth + "(?:localhost|(?:(?:" + e.re.src_domain + ")\\.)+" + e.re.src_domain_root + ")" + e.re.src_port + e.re.src_host_terminator + e.re.src_path, "i")), e.re.no_http.test(i) ? t >= 3 && n[t - 3] === ":" || t >= 3 && n[t - 3] === "/" ? 0 : i.match(e.re.no_http)[0].length : 0
                }
            },
            "mailto:": {
                validate: function(n, t, e) {
                    var i = n.slice(t);
                    return e.re.mailto || (e.re.mailto = new RegExp("^" + e.re.src_email_name + "@" + e.re.src_host_strict, "i")), e.re.mailto.test(i) ? i.match(e.re.mailto)[0].length : 0
                }
            }
        },
        xp = "a[cdefgilmnoqrstuwxz]|b[abdefghijmnorstvwyz]|c[acdfghiklmnoruvwxyz]|d[ejkmoz]|e[cegrstu]|f[ijkmor]|g[abdefghilmnpqrstuwy]|h[kmnrtu]|i[delmnoqrst]|j[emop]|k[eghimnprwyz]|l[abcikrstuvy]|m[acdeghklmnopqrstuvwxyz]|n[acefgilopruz]|om|p[aefghklmnrstwy]|qa|r[eosuw]|s[abcdeghijklmnortuvxyz]|t[cdfghjklmnortvwz]|u[agksyz]|v[aceginu]|w[fs]|y[et]|z[amw]",
        kp = "biz|com|edu|gov|net|org|pro|web|xxx|aero|asia|coop|info|museum|name|shop|\u0440\u0444".split("|");

    function Cp(n) {
        n.__index__ = -1, n.__text_cache__ = ""
    }

    function Ep(n) {
        return function(t, e) {
            var i = t.slice(e);
            return n.test(i) ? i.match(n)[0].length : 0
        }
    }

    function dc() {
        return function(n, t) {
            t.normalize(n)
        }
    }

    function bi(n) {
        var t = n.re = uc()(n.__opts__),
            e = n.__tlds__.slice();
        n.onCompile(), n.__tlds_replaced__ || e.push(xp), e.push(t.src_xn), t.src_tlds = e.join("|");

        function i(a) {
            return a.replace("%TLDS%", t.src_tlds)
        }
        t.email_fuzzy = RegExp(i(t.tpl_email_fuzzy), "i"), t.link_fuzzy = RegExp(i(t.tpl_link_fuzzy), "i"), t.link_no_ip_fuzzy = RegExp(i(t.tpl_link_no_ip_fuzzy), "i"), t.host_fuzzy_test = RegExp(i(t.tpl_host_fuzzy_test), "i");
        var r = [];
        n.__compiled__ = {};

        function o(a, l) {
            throw new Error('(LinkifyIt) Invalid schema "' + a + '": ' + l)
        }
        Object.keys(n.__schemas__).forEach(function(a) {
            var l = n.__schemas__[a];
            if (l !== null) {
                var c = {
                    validate: null,
                    link: null
                };
                if (n.__compiled__[a] = c, gp(l)) {
                    bp(l.validate) ? c.validate = Ep(l.validate) : hc(l.validate) ? c.validate = l.validate : o(a, l), hc(l.normalize) ? c.normalize = l.normalize : l.normalize ? o(a, l) : c.normalize = dc();
                    return
                }
                if (mp(l)) {
                    r.push(a);
                    return
                }
                o(a, l)
            }
        }), r.forEach(function(a) {
            n.__compiled__[n.__schemas__[a]] && (n.__compiled__[a].validate = n.__compiled__[n.__schemas__[a]].validate, n.__compiled__[a].normalize = n.__compiled__[n.__schemas__[a]].normalize)
        }), n.__compiled__[""] = {
            validate: null,
            normalize: dc()
        };
        var s = Object.keys(n.__compiled__).filter(function(a) {
            return a.length > 0 && n.__compiled__[a]
        }).map(vp).join("|");
        n.re.schema_test = RegExp("(^|(?!_)(?:[><\uFF5C]|" + t.src_ZPCc + "))(" + s + ")", "i"), n.re.schema_search = RegExp("(^|(?!_)(?:[><\uFF5C]|" + t.src_ZPCc + "))(" + s + ")", "ig"), n.re.schema_at_start = RegExp("^" + n.re.schema_search.source, "i"), n.re.pretest = RegExp("(" + n.re.schema_test.source + ")|(" + n.re.host_fuzzy_test.source + ")|@", "i"), Cp(n)
    }

    function _p(n, t) {
        var e = n.__index__,
            i = n.__last_index__,
            r = n.__text_cache__.slice(e, i);
        this.schema = n.__schema__.toLowerCase(), this.index = e + t, this.lastIndex = i + t, this.raw = r, this.text = r, this.url = r
    }

    function go(n, t) {
        var e = new _p(n, t);
        return n.__compiled__[e.schema].normalize(e, n), e
    }

    function gt(n, t) {
        if (!(this instanceof gt)) return new gt(n, t);
        t || wp(n) && (t = n, n = {}), this.__opts__ = mo({}, pc, t), this.__index__ = -1, this.__last_index__ = -1, this.__schema__ = "", this.__text_cache__ = "", this.__schemas__ = mo({}, yp, n), this.__compiled__ = {}, this.__tlds__ = kp, this.__tlds_replaced__ = !1, this.re = {}, bi(this)
    }
    gt.prototype.add = function(t, e) {
        return this.__schemas__[t] = e, bi(this), this
    };
    gt.prototype.set = function(t) {
        return this.__opts__ = mo(this.__opts__, t), this
    };
    gt.prototype.test = function(t) {
        if (this.__text_cache__ = t, this.__index__ = -1, !t.length) return !1;
        var e, i, r, o, s, a, l, c, u;
        if (this.re.schema_test.test(t)) {
            for (l = this.re.schema_search, l.lastIndex = 0;
                (e = l.exec(t)) !== null;)
                if (o = this.testSchemaAt(t, e[2], l.lastIndex), o) {
                    this.__schema__ = e[2], this.__index__ = e.index + e[1].length, this.__last_index__ = e.index + e[0].length + o;
                    break
                }
        }
        return this.__opts__.fuzzyLink && this.__compiled__["http:"] && (c = t.search(this.re.host_fuzzy_test), c >= 0 && (this.__index__ < 0 || c < this.__index__) && (i = t.match(this.__opts__.fuzzyIP ? this.re.link_fuzzy : this.re.link_no_ip_fuzzy)) !== null && (s = i.index + i[1].length, (this.__index__ < 0 || s < this.__index__) && (this.__schema__ = "", this.__index__ = s, this.__last_index__ = i.index + i[0].length))), this.__opts__.fuzzyEmail && this.__compiled__["mailto:"] && (u = t.indexOf("@"), u >= 0 && (r = t.match(this.re.email_fuzzy)) !== null && (s = r.index + r[1].length, a = r.index + r[0].length, (this.__index__ < 0 || s < this.__index__ || s === this.__index__ && a > this.__last_index__) && (this.__schema__ = "mailto:", this.__index__ = s, this.__last_index__ = a))), this.__index__ >= 0
    };
    gt.prototype.pretest = function(t) {
        return this.re.pretest.test(t)
    };
    gt.prototype.testSchemaAt = function(t, e, i) {
        return this.__compiled__[e.toLowerCase()] ? this.__compiled__[e.toLowerCase()].validate(t, i, this) : 0
    };
    gt.prototype.match = function(t) {
        var e = 0,
            i = [];
        this.__index__ >= 0 && this.__text_cache__ === t && (i.push(go(this, e)), e = this.__last_index__);
        for (var r = e ? t.slice(e) : t; this.test(r);) i.push(go(this, e)), r = r.slice(this.__last_index__), e += this.__last_index__;
        return i.length ? i : null
    };
    gt.prototype.matchAtStart = function(t) {
        if (this.__text_cache__ = t, this.__index__ = -1, !t.length) return null;
        var e = this.re.schema_at_start.exec(t);
        if (!e) return null;
        var i = this.testSchemaAt(t, e[2], e[0].length);
        return i ? (this.__schema__ = e[2], this.__index__ = e.index + e[1].length, this.__last_index__ = e.index + e[0].length + i, go(this, 0)) : null
    };
    gt.prototype.tlds = function(t, e) {
        return t = Array.isArray(t) ? t : [t], e ? (this.__tlds__ = this.__tlds__.concat(t).sort().filter(function(i, r, o) {
            return i !== o[r - 1]
        }).reverse(), bi(this), this) : (this.__tlds__ = t.slice(), this.__tlds_replaced__ = !0, bi(this), this)
    };
    gt.prototype.normalize = function(t) {
        t.schema || (t.url = "http://" + t.url), t.schema === "mailto:" && !/^mailto:/i.test(t.url) && (t.url = "mailto:" + t.url)
    };
    gt.prototype.onCompile = function() {};
    fc.exports = gt
});
var Cc = {};
Se(Cc, {
    decode: () => yo,
    default: () => Mp,
    encode: () => xo,
    toASCII: () => kc,
    toUnicode: () => xc,
    ucs2decode: () => wo,
    ucs2encode: () => wc
});

function Vt(n) {
    throw new RangeError(Lp[n])
}

function Tp(n, t) {
    let e = [],
        i = n.length;
    for (; i--;) e[i] = t(n[i]);
    return e
}

function vc(n, t) {
    let e = n.split("@"),
        i = "";
    e.length > 1 && (i = e[0] + "@", n = e[1]), n = n.replace(Dp, ".");
    let r = n.split("."),
        o = Tp(r, t).join(".");
    return i + o
}

function wo(n) {
    let t = [],
        e = 0,
        i = n.length;
    for (; e < i;) {
        let r = n.charCodeAt(e++);
        if (r >= 55296 && r <= 56319 && e < i) {
            let o = n.charCodeAt(e++);
            (o & 64512) == 56320 ? t.push(((r & 1023) << 10) + (o & 1023) + 65536) : (t.push(r), e--)
        } else t.push(r)
    }
    return t
}
var bc, Sp, Ap, Dp, Lp, bo, Tt, vo, wc, $p, gc, yc, yo, xo, xc, kc, Ip, Mp, Ec = qu(() => {
    "use strict";
    bc = "-", Sp = /^xn--/, Ap = /[^\0-\x7F]/, Dp = /[\x2E\u3002\uFF0E\uFF61]/g, Lp = {
        overflow: "Overflow: input needs wider integers to process",
        "not-basic": "Illegal input >= 0x80 (not a basic code point)",
        "invalid-input": "Invalid input"
    }, bo = 36 - 1, Tt = Math.floor, vo = String.fromCharCode;
    wc = n => String.fromCodePoint(...n), $p = function(n) {
        return n >= 48 && n < 58 ? 26 + (n - 48) : n >= 65 && n < 91 ? n - 65 : n >= 97 && n < 123 ? n - 97 : 36
    }, gc = function(n, t) {
        return n + 22 + 75 * (n < 26) - ((t != 0) << 5)
    }, yc = function(n, t, e) {
        let i = 0;
        for (n = e ? Tt(n / 700) : n >> 1, n += Tt(n / t); n > bo * 26 >> 1; i += 36) n = Tt(n / bo);
        return Tt(i + (bo + 1) * n / (n + 38))
    }, yo = function(n) {
        let t = [],
            e = n.length,
            i = 0,
            r = 128,
            o = 72,
            s = n.lastIndexOf(bc);
        s < 0 && (s = 0);
        for (let a = 0; a < s; ++a) n.charCodeAt(a) >= 128 && Vt("not-basic"), t.push(n.charCodeAt(a));
        for (let a = s > 0 ? s + 1 : 0; a < e;) {
            let l = i;
            for (let u = 1, h = 36;; h += 36) {
                a >= e && Vt("invalid-input");
                let d = $p(n.charCodeAt(a++));
                d >= 36 && Vt("invalid-input"), d > Tt((2147483647 - i) / u) && Vt("overflow"), i += d * u;
                let f = h <= o ? 1 : h >= o + 26 ? 26 : h - o;
                if (d < f) break;
                let p = 36 - f;
                u > Tt(2147483647 / p) && Vt("overflow"), u *= p
            }
            let c = t.length + 1;
            o = yc(i - l, c, l == 0), Tt(i / c) > 2147483647 - r && Vt("overflow"), r += Tt(i / c), i %= c, t.splice(i++, 0, r)
        }
        return String.fromCodePoint(...t)
    }, xo = function(n) {
        let t = [];
        n = wo(n);
        let e = n.length,
            i = 128,
            r = 0,
            o = 72;
        for (let l of n) l < 128 && t.push(vo(l));
        let s = t.length,
            a = s;
        for (s && t.push(bc); a < e;) {
            let l = 2147483647;
            for (let u of n) u >= i && u < l && (l = u);
            let c = a + 1;
            l - i > Tt((2147483647 - r) / c) && Vt("overflow"), r += (l - i) * c, i = l;
            for (let u of n)
                if (u < i && ++r > 2147483647 && Vt("overflow"), u === i) {
                    let h = r;
                    for (let d = 36;; d += 36) {
                        let f = d <= o ? 1 : d >= o + 26 ? 26 : d - o;
                        if (h < f) break;
                        let p = h - f,
                            m = 36 - f;
                        t.push(vo(gc(f + p % m, 0))), h = Tt(p / m)
                    }
                    t.push(vo(gc(h, 0))), o = yc(r, c, a === s), r = 0, ++a
                }++ r, ++i
        }
        return t.join("")
    }, xc = function(n) {
        return vc(n, function(t) {
            return Sp.test(t) ? yo(t.slice(4).toLowerCase()) : t
        })
    }, kc = function(n) {
        return vc(n, function(t) {
            return Ap.test(t) ? "xn--" + xo(t) : t
        })
    }, Ip = {
        version: "2.1.0",
        ucs2: {
            decode: wo,
            encode: wc
        },
        decode: yo,
        encode: xo,
        toASCII: kc,
        toUnicode: xc
    }, Mp = Ip
});
var Sc = _((Rv, _c) => {
    "use strict";
    _c.exports = {
        options: {
            html: !1,
            xhtmlOut: !1,
            breaks: !1,
            langPrefix: "language-",
            linkify: !1,
            typographer: !1,
            quotes: "\u201C\u201D\u2018\u2019",
            highlight: null,
            maxNesting: 100
        },
        components: {
            core: {},
            block: {},
            inline: {}
        }
    }
});
var Dc = _((Nv, Ac) => {
    "use strict";
    Ac.exports = {
        options: {
            html: !1,
            xhtmlOut: !1,
            breaks: !1,
            langPrefix: "language-",
            linkify: !1,
            typographer: !1,
            quotes: "\u201C\u201D\u2018\u2019",
            highlight: null,
            maxNesting: 20
        },
        components: {
            core: {
                rules: ["normalize", "block", "inline", "text_join"]
            },
            block: {
                rules: ["paragraph"]
            },
            inline: {
                rules: ["text"],
                rules2: ["balance_pairs", "fragments_join"]
            }
        }
    }
});
var Tc = _((zv, Lc) => {
    "use strict";
    Lc.exports = {
        options: {
            html: !0,
            xhtmlOut: !0,
            breaks: !1,
            langPrefix: "language-",
            linkify: !1,
            typographer: !1,
            quotes: "\u201C\u201D\u2018\u2019",
            highlight: null,
            maxNesting: 20
        },
        components: {
            core: {
                rules: ["normalize", "block", "inline", "text_join"]
            },
            block: {
                rules: ["blockquote", "code", "fence", "heading", "hr", "html_block", "lheading", "list", "reference", "paragraph"]
            },
            inline: {
                rules: ["autolink", "backticks", "emphasis", "entity", "escape", "html_inline", "image", "link", "newline", "text"],
                rules2: ["balance_pairs", "emphasis", "fragments_join"]
            }
        }
    }
});
var Fc = _((Hv, Mc) => {
    "use strict";
    var Ye = N(),
        Fp = fa(),
        qp = ga(),
        Bp = Ua(),
        Pp = _l(),
        Op = lc(),
        Rp = mc(),
        Qt = Gr(),
        $c = (Ec(), Bu(Cc)),
        Np = {
            default: Sc(),
            zero: Dc(),
            commonmark: Tc()
        },
        zp = /^(vbscript|javascript|file|data):/,
        Hp = /^data:image\/(gif|png|jpeg|webp);/;

    function Up(n) {
        var t = n.trim().toLowerCase();
        return zp.test(t) ? !!Hp.test(t) : !0
    }
    var Ic = ["http:", "https:", "mailto:"];

    function jp(n) {
        var t = Qt.parse(n, !0);
        if (t.hostname && (!t.protocol || Ic.indexOf(t.protocol) >= 0)) try {
            t.hostname = $c.toASCII(t.hostname)
        } catch {}
        return Qt.encode(Qt.format(t))
    }

    function Vp(n) {
        var t = Qt.parse(n, !0);
        if (t.hostname && (!t.protocol || Ic.indexOf(t.protocol) >= 0)) try {
            t.hostname = $c.toUnicode(t.hostname)
        } catch {}
        return Qt.decode(Qt.format(t), Qt.decode.defaultChars + "%")
    }

    function bt(n, t) {
        if (!(this instanceof bt)) return new bt(n, t);
        t || Ye.isString(n) || (t = n || {}, n = "default"), this.inline = new Op, this.block = new Pp, this.core = new Bp, this.renderer = new qp, this.linkify = new Rp, this.validateLink = Up, this.normalizeLink = jp, this.normalizeLinkText = Vp, this.utils = Ye, this.helpers = Ye.assign({}, Fp), this.options = {}, this.configure(n), t && this.set(t)
    }
    bt.prototype.set = function(n) {
        return Ye.assign(this.options, n), this
    };
    bt.prototype.configure = function(n) {
        var t = this,
            e;
        if (Ye.isString(n) && (e = n, n = Np[e], !n)) throw new Error('Wrong `markdown-it` preset "' + e + '", check name');
        if (!n) throw new Error("Wrong `markdown-it` preset, can't be empty");
        return n.options && t.set(n.options), n.components && Object.keys(n.components).forEach(function(i) {
            n.components[i].rules && t[i].ruler.enableOnly(n.components[i].rules), n.components[i].rules2 && t[i].ruler2.enableOnly(n.components[i].rules2)
        }), this
    };
    bt.prototype.enable = function(n, t) {
        var e = [];
        Array.isArray(n) || (n = [n]), ["core", "block", "inline"].forEach(function(r) {
            e = e.concat(this[r].ruler.enable(n, !0))
        }, this), e = e.concat(this.inline.ruler2.enable(n, !0));
        var i = n.filter(function(r) {
            return e.indexOf(r) < 0
        });
        if (i.length && !t) throw new Error("MarkdownIt. Failed to enable unknown rule(s): " + i);
        return this
    };
    bt.prototype.disable = function(n, t) {
        var e = [];
        Array.isArray(n) || (n = [n]), ["core", "block", "inline"].forEach(function(r) {
            e = e.concat(this[r].ruler.disable(n, !0))
        }, this), e = e.concat(this.inline.ruler2.disable(n, !0));
        var i = n.filter(function(r) {
            return e.indexOf(r) < 0
        });
        if (i.length && !t) throw new Error("MarkdownIt. Failed to disable unknown rule(s): " + i);
        return this
    };
    bt.prototype.use = function(n) {
        var t = [this].concat(Array.prototype.slice.call(arguments, 1));
        return n.apply(n, t), this
    };
    bt.prototype.parse = function(n, t) {
        if (typeof n != "string") throw new Error("Input data should be a String");
        var e = new this.core.State(n, this, t);
        return this.core.process(e), e.tokens
    };
    bt.prototype.render = function(n, t) {
        return t = t || {}, this.renderer.render(this.parse(n, t), this.options, t)
    };
    bt.prototype.parseInline = function(n, t) {
        var e = new this.core.State(n, this, t);
        return e.inlineMode = !0, this.core.process(e), e.tokens
    };
    bt.prototype.renderInline = function(n, t) {
        return t = t || {}, this.renderer.render(this.parseInline(n, t), this.options, t)
    };
    Mc.exports = bt
});
var Bc = _((Uv, qc) => {
    "use strict";
    qc.exports = Fc()
});
var zc = _((jv, Nc) => {
    var ko = !0,
        Oc = !1,
        Rc = !1;
    Nc.exports = function(n, t) {
        t && (ko = !t.enabled, Oc = !!t.label, Rc = !!t.labelAfter), n.core.ruler.after("inline", "github-task-lists", function(e) {
            for (var i = e.tokens, r = 2; r < i.length; r++) Gp(i, r) && (Kp(i[r], e.Token), Pc(i[r - 2], "class", "task-list-item" + (ko ? "" : " enabled")), Pc(i[Wp(i, r - 2)], "class", "contains-task-list"))
        })
    };

    function Pc(n, t, e) {
        var i = n.attrIndex(t),
            r = [t, e];
        i < 0 ? n.attrPush(r) : n.attrs[i] = r
    }

    function Wp(n, t) {
        for (var e = n[t].level - 1, i = t - 1; i >= 0; i--)
            if (n[i].level === e) return i;
        return -1
    }

    function Gp(n, t) {
        return Qp(n[t]) && tf(n[t - 1]) && ef(n[t - 2]) && nf(n[t])
    }

    function Kp(n, t) {
        if (n.children.unshift(Zp(n, t)), n.children[1].content = n.children[1].content.slice(3), n.content = n.content.slice(3), Oc)
            if (Rc) {
                n.children.pop();
                var e = "task-item-" + Math.ceil(Math.random() * (1e4 * 1e3) - 1e3);
                n.children[0].content = n.children[0].content.slice(0, -1) + ' id="' + e + '">', n.children.push(Jp(n.content, e, t))
            } else n.children.unshift(Xp(t)), n.children.push(Yp(t))
    }

    function Zp(n, t) {
        var e = new t("html_inline", "", 0),
            i = ko ? ' disabled="" ' : "";
        return n.content.indexOf("[ ] ") === 0 ? e.content = '<input class="task-list-item-checkbox"' + i + 'type="checkbox">' : (n.content.indexOf("[x] ") === 0 || n.content.indexOf("[X] ") === 0) && (e.content = '<input class="task-list-item-checkbox" checked=""' + i + 'type="checkbox">'), e
    }

    function Xp(n) {
        var t = new n("html_inline", "", 0);
        return t.content = "<label>", t
    }

    function Yp(n) {
        var t = new n("html_inline", "", 0);
        return t.content = "</label>", t
    }

    function Jp(n, t, e) {
        var i = new e("html_inline", "", 0);
        return i.content = '<label class="task-list-item-label" for="' + t + '">' + n + "</label>", i.attrs = [{
            for: t
        }], i
    }

    function Qp(n) {
        return n.type === "inline"
    }

    function tf(n) {
        return n.type === "paragraph_open"
    }

    function ef(n) {
        return n.type === "list_item_open"
    }

    function nf(n) {
        return n.content.indexOf("[ ] ") === 0 || n.content.indexOf("[x] ") === 0 || n.content.indexOf("[X] ") === 0
    }
});
var dr = {};
Se(dr, {
    emit: () => ur,
    emitPublic: () => Nu,
    error: () => hr,
    listen: () => Ru,
    showResponseError: () => Uu,
    showValidationErrors: () => Hu,
    success: () => zu
});
var on = {},
    Ou = [];

function ur(n, t) {
    Ou.push({
        name: n,
        data: t
    });
    let e = on[n] || [];
    for (let i of e) i(t)
}

function Ru(n, t) {
    typeof on[n] > "u" && (on[n] = []), on[n].push(t)
}

function Nu(n, t, e) {
    let i = new CustomEvent(t, {
        detail: e,
        bubbles: !0
    });
    n.dispatchEvent(i)
}

function zu(n) {
    ur("success", n)
}

function hr(n) {
    ur("error", n)
}

function Hu(n) {
    if (n.status && n.status === 422 && n.data) {
        let t = Object.values(n.data).flat().join(`
`);
        hr(t)
    }
}

function Uu(n) {
    n.status && n.status >= 400 && n.data && n.data.message && hr(n.data.message)
}
var pr = {};
Se(pr, {
    HttpError: () => sn,
    createXMLHttpRequest: () => Vu,
    delete: () => Xu,
    get: () => Wu,
    patch: () => Zu,
    post: () => Gu,
    put: () => Ku
});
async function ju(n) {
    if (n.status === 204) return null;
    let e = (n.headers.get("Content-Type") || "").split(";")[0].split("/").pop();
    return e === "javascript" || e === "json" ? n.json() : n.text()
}
var sn = class extends Error {
    constructor(t, e) {
        super(t.statusText), this.data = e, this.headers = t.headers, this.redirected = t.redirected, this.status = t.status, this.statusText = t.statusText, this.url = t.url, this.original = t
    }
};

function Vu(n, t, e = {}) {
    let i = document.querySelector("meta[name=token]").getAttribute("content"),
        r = new XMLHttpRequest;
    for (let [o, s] of Object.entries(e)) r.addEventListener(o, s.bind(r));
    return r.open(n, t), r.withCredentials = !0, r.setRequestHeader("X-CSRF-TOKEN", i), r
}
async function Go(n, t = {}) {
    let e = n;
    if (e.startsWith("http") || (e = window.baseUrl(e)), t.params) {
        let l = new URL(e);
        for (let c of Object.keys(t.params)) {
            let u = t.params[c];
            typeof u < "u" && u !== null && l.searchParams.set(c, u)
        }
        e = l.toString()
    }
    let i = document.querySelector("meta[name=token]").getAttribute("content"),
        r = {
            ...t,
            credentials: "same-origin"
        };
    r.headers = {
        ...r.headers || {},
        baseURL: window.baseUrl(""),
        "X-CSRF-TOKEN": i
    };
    let o = await fetch(e, r),
        s = await ju(o),
        a = {
            data: s,
            headers: o.headers,
            redirected: o.redirected,
            status: o.status,
            statusText: o.statusText,
            url: o.url,
            original: o
        };
    if (!o.ok) throw new sn(o, s);
    return a
}
async function an(n, t, e = null) {
    let i = {
        method: n,
        body: e
    };
    return typeof e == "object" && !(e instanceof FormData) && (i.headers = {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
    }, i.body = JSON.stringify(e)), e instanceof FormData && n !== "post" && (e.append("_method", n), i.method = "post"), Go(t, i)
}
async function Wu(n, t = {}) {
    return Go(n, {
        method: "GET",
        params: t
    })
}
async function Gu(n, t = null) {
    return an("POST", n, t)
}
async function Ku(n, t = null) {
    return an("PUT", n, t)
}
async function Zu(n, t = null) {
    return an("PATCH", n, t)
}
async function Xu(n, t = null) {
    return an("DELETE", n, t)
}
var fr = class {
        constructor() {
            this.store = new Map, this.parseTranslations()
        }
        parseTranslations() {
            let t = document.querySelectorAll('meta[name="translation"]');
            for (let e of t) {
                let i = e.getAttribute("key"),
                    r = e.getAttribute("value");
                this.store.set(i, r)
            }
        }
        get(t, e) {
            let i = this.getTransText(t);
            return this.performReplacements(i, e)
        }
        getPlural(t, e, i) {
            let r = this.getTransText(t);
            return this.parsePlural(r, e, i)
        }
        parsePlural(t, e, i) {
            let r = t.split("|"),
                o = /^{([0-9]+)}/,
                s = /^\[([0-9]+),([0-9*]+)]/,
                a = null;
            for (let l of r) {
                let c = l.match(o);
                if (c !== null && Number(c[1]) === e) {
                    a = l.replace(o, "").trim();
                    break
                }
                let u = l.match(s);
                if (u !== null && Number(u[1]) <= e && (u[2] === "*" || Number(u[2]) >= e)) {
                    a = l.replace(s, "").trim();
                    break
                }
            }
            return a === null && r.length > 1 && (a = e === 1 ? r[0] : r[1]), a === null && (a = r[0]), this.performReplacements(a, i)
        }
        getTransText(t) {
            let e = this.store.get(t);
            return e === void 0 && console.warn(`Translation with key "${t}" does not exist`), e
        }
        performReplacements(t, e) {
            if (!e) return t;
            let i = t.match(/:(\S+)/g);
            if (i === null) return t;
            let r = t;
            return i.forEach(o => {
                let s = o.substring(1);
                typeof e[s] > "u" || (r = r.replace(o, e[s]))
            }), r
        }
    },
    Ko = fr;
var wr = {};
Se(wr, {
    first: () => th,
    firstOnElement: () => nh,
    get: () => eh,
    init: () => br,
    register: () => vr
});

function mr(n) {
    let t = i => i.slice(0, 1).toUpperCase() + i.slice(1),
        e = n.split("-");
    return e[0] + e.slice(1).map(t).join("")
}

function Zo(n) {
    return n.replace(/[A-Z]/g, (t, e) => (e > 0 ? "-" : "") + t.toLowerCase())
}
var Ae = {},
    Xo = {},
    gr = new WeakMap;

function Yu(n, t) {
    let e = {},
        i = {},
        r = `${n}@`,
        o = `[refs*="${r}"]`,
        s = [...t.querySelectorAll(o)];
    t.matches(o) && s.push(t);
    for (let a of s) {
        let l = a.getAttribute("refs").split(" ").filter(c => c.startsWith(r)).map(c => c.replace(r, "")).map(mr);
        for (let c of l) e[c] = a, typeof i[c] > "u" && (i[c] = []), i[c].push(a)
    }
    return {
        refs: e,
        manyRefs: i
    }
}

function Ju(n, t) {
    let e = {},
        i = `option:${n}:`;
    for (let {
            name: r,
            value: o
        }
        of t.attributes)
        if (r.startsWith(i)) {
            let s = r.replace(i, "");
            e[mr(s)] = o || ""
        } return e
}

function Qu(n, t) {
    let e = Xo[n];
    if (e === void 0) return;
    let i;
    try {
        i = new e, i.$name = n, i.$el = t;
        let o = Yu(n, t);
        i.$refs = o.refs, i.$manyRefs = o.manyRefs, i.$opts = Ju(n, t), i.setup()
    } catch (o) {
        console.error("Failed to create component", o, n, t)
    }
    typeof Ae[n] > "u" && (Ae[n] = []), Ae[n].push(i);
    let r = gr.get(t) || {};
    r[n] = i, gr.set(t, r)
}

function br(n = document) {
    let t = n.querySelectorAll("[component],[components]");
    for (let e of t) {
        let i = `${e.getAttribute("component")||""} ${e.getAttribute("components")}`.toLowerCase().split(" ").filter(Boolean);
        for (let r of i) Qu(r, e)
    }
}

function vr(n) {
    let t = Object.keys(n);
    for (let e of t) Xo[Zo(e)] = n[e]
}

function th(n) {
    return (Ae[n] || [null])[0]
}

function eh(n) {
    return Ae[n] || []
}

function nh(n, t) {
    return (gr.get(n) || {})[t] || null
}
var Uo = {};
Se(Uo, {
    AddRemoveRows: () => cn,
    AjaxDeleteRow: () => un,
    AjaxForm: () => hn,
    Attachments: () => dn,
    AttachmentsList: () => pn,
    AutoSubmit: () => mn,
    AutoSuggest: () => fn,
    BackToTop: () => gn,
    BookSort: () => Fn,
    ChapterContents: () => Bn,
    CodeEditor: () => Pn,
    CodeHighlighter: () => On,
    CodeTextarea: () => Rn,
    Collapsible: () => Nn,
    ConfirmDialog: () => zn,
    CustomCheckbox: () => Hn,
    DetailsHighlighter: () => Un,
    Dropdown: () => jn,
    DropdownSearch: () => Vn,
    Dropzone: () => Wn,
    EditorToolbox: () => Gn,
    EntityPermissions: () => Kn,
    EntitySearch: () => Zn,
    EntitySelector: () => Xn,
    EntitySelectorPopup: () => Yn,
    EventEmitSelect: () => Jn,
    ExpandToggle: () => Qn,
    GlobalSearch: () => ti,
    HeaderMobileToggle: () => ei,
    ImageManager: () => ni,
    ImagePicker: () => ii,
    ListSortControl: () => ri,
    MarkdownEditor: () => Mi,
    NewUserPassword: () => Fi,
    Notification: () => qi,
    OptionalInput: () => Bi,
    PageComment: () => Pi,
    PageComments: () => Oi,
    PageDisplay: () => Ri,
    PageEditor: () => Ni,
    PagePicker: () => Hi,
    PermissionsTable: () => Ui,
    Pointer: () => ji,
    Popup: () => Vi,
    SettingAppColorScheme: () => Wi,
    SettingColorPicker: () => Gi,
    SettingHomepageControl: () => Ki,
    ShelfSort: () => Zi,
    ShortcutInput: () => Yi,
    Shortcuts: () => Xi,
    SortableList: () => Ji,
    SubmitOnChange: () => Qi,
    Tabs: () => tr,
    TagManager: () => er,
    TemplateManager: () => nr,
    ToggleSwitch: () => ir,
    TriLayout: () => rr,
    UserSelect: () => or,
    WebhookEvents: () => sr,
    WysiwygEditor: () => cr
});

function Et(n, t = {}, e = []) {
    let i = document.createElement(n);
    for (let [r, o] of Object.entries(t)) o === null ? i.removeAttribute(r) : i.setAttribute(r, o);
    for (let r of e) typeof r == "string" ? i.append(document.createTextNode(r)) : i.append(r);
    return i
}

function yr(n, t) {
    let e = document.querySelectorAll(n);
    for (let i of e) t(i)
}

function ln(n, t, e) {
    for (let i of t) n.addEventListener(i, e)
}

function R(n, t) {
    Array.isArray(n) || (n = [n]);
    for (let e of n) e.addEventListener("click", t), e.addEventListener("keydown", i => {
        (i.key === "Enter" || i.key === " ") && (i.preventDefault(), t(i))
    })
}

function Yo(n, t, e) {
    Array.isArray(t) || (t = [t]);
    let i = r => {
        r.key === n && e(r)
    };
    t.forEach(r => r.addEventListener("keydown", i))
}

function se(n, t) {
    Yo("Enter", n, t)
}

function Jo(n, t) {
    Yo("Escape", n, t)
}

function K(n, t, e, i) {
    n.addEventListener(e, r => {
        let o = r.target.closest(t);
        o && i.call(o, r, o)
    })
}

function Qo(n, t) {
    let e = document.querySelectorAll(n);
    t = t.toLowerCase();
    for (let i of e)
        if (i.textContent.toLowerCase().includes(t)) return i;
    return null
}

function De(n) {
    n.innerHTML = '<div class="loading-container"><div></div><div></div><div></div></div>'
}

function ae() {
    let n = document.createElement("div");
    return n.classList.add("loading-container"), n.innerHTML = "<div></div><div></div><div></div>", n
}

function Le(n) {
    let t = n.querySelectorAll(".loading-container");
    for (let e of t) e.remove()
}

function _t(n) {
    let t = document.createElement("div");
    return t.innerHTML = n, window.$components.init(t), t.children[0]
}

function Nt(n, t, e) {
    let i;
    return function(...o) {
        let s = this,
            a = function() {
                i = null, e || n.apply(s, o)
            },
            l = e && !i;
        clearTimeout(i), i = setTimeout(a, t), l && n.apply(s, o)
    }
}

function kr(n) {
    if (!n) return;
    let t = n.closest("details");
    t && !t.open && (t.open = !0), n.scrollIntoView({
        behavior: "smooth"
    });
    let e = getComputedStyle(document.body).getPropertyValue("--color-link");
    n.style.outline = `2px dashed ${e}`, n.style.outlineOffset = "5px", n.style.transition = null, setTimeout(() => {
        n.style.transition = "outline linear 3s", n.style.outline = "2px dashed rgba(0, 0, 0, 0)";
        let i = () => {
            n.removeEventListener("transitionend", i), n.style.transition = null, n.style.outline = null, n.style.outlineOffset = null
        };
        n.addEventListener("transitionend", i)
    }, 1e3)
}

function ts(n) {
    return n.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;")
}

function es() {
    let n = () => ((1 + Math.random()) * 65536 | 0).toString(16).substring(1);
    return `${n()+n()}-${n()}-${n()}-${n()}-${n()}${n()}${n()}`
}

function ns(n) {
    return new Promise(t => {
        setTimeout(t, n)
    })
}
var g = class {
    constructor() {
        at(this, "$name", "");
        at(this, "$el", null);
        at(this, "$refs", {});
        at(this, "$manyRefs", {});
        at(this, "$opts", {})
    }
    setup() {}
    $emit(t, e = {}) {
        e.from = this;
        let i = this.$name,
            r = new CustomEvent(`${i}-${t}`, {
                bubbles: !0,
                detail: e
            });
        this.$el.dispatchEvent(r)
    }
};
var cn = class extends g {
    setup() {
        this.modelRow = this.$refs.model, this.addButton = this.$refs.add, this.removeSelector = this.$opts.removeSelector, this.rowSelector = this.$opts.rowSelector, this.setupListeners()
    }
    setupListeners() {
        this.addButton.addEventListener("click", this.add.bind(this)), K(this.$el, this.removeSelector, "click", t => {
            t.target.closest(this.rowSelector).remove()
        })
    }
    add() {
        let t = this.modelRow.cloneNode(!0);
        t.classList.remove("hidden"), this.setClonedInputNames(t), this.modelRow.parentNode.insertBefore(t, this.modelRow), window.$components.init(t)
    }
    setClonedInputNames(t) {
        let e = es(),
            i = t.querySelectorAll('[name*="randrowid"]');
        for (let r of i) r.name = r.name.split("randrowid").join(e)
    }
};
var un = class extends g {
    setup() {
        this.row = this.$el, this.url = this.$opts.url, this.deleteButtons = this.$manyRefs.delete, R(this.deleteButtons, this.runDelete.bind(this))
    }
    runDelete() {
        this.row.style.opacity = "0.7", this.row.style.pointerEvents = "none", window.$http.delete(this.url).then(t => {
            typeof t.data == "object" && t.data.message && window.$events.emit("success", t.data.message), this.row.remove()
        }).catch(() => {
            this.row.style.opacity = null, this.row.style.pointerEvents = null
        })
    }
};
var hn = class extends g {
    setup() {
        this.container = this.$el, this.responseContainer = this.container, this.url = this.$opts.url, this.method = this.$opts.method || "post", this.successMessage = this.$opts.successMessage, this.submitButtons = this.$manyRefs.submit || [], this.$opts.responseContainer && (this.responseContainer = this.container.closest(this.$opts.responseContainer)), this.setupListeners()
    }
    setupListeners() {
        if (this.container.tagName === "FORM") {
            this.container.addEventListener("submit", this.submitRealForm.bind(this));
            return
        }
        se(this.container, t => {
            this.submitFakeForm(), t.preventDefault()
        }), this.submitButtons.forEach(t => R(t, this.submitFakeForm.bind(this)))
    }
    submitFakeForm() {
        let t = new FormData,
            e = this.container.querySelectorAll("[name]");
        for (let i of e) t.append(i.getAttribute("name"), i.value);
        this.submit(t)
    }
    submitRealForm(t) {
        t.preventDefault();
        let e = new FormData(this.container);
        this.submit(e)
    }
    async submit(t) {
        this.responseContainer.style.opacity = "0.7", this.responseContainer.style.pointerEvents = "none";
        try {
            let e = await window.$http[this.method.toLowerCase()](this.url, t);
            this.$emit("success", {
                formData: t
            }), this.responseContainer.innerHTML = e.data, this.successMessage && window.$events.emit("success", this.successMessage)
        } catch (e) {
            this.responseContainer.innerHTML = e.data
        }
        window.$components.init(this.responseContainer), this.responseContainer.style.opacity = null, this.responseContainer.style.pointerEvents = null
    }
};
var dn = class extends g {
    setup() {
        this.container = this.$el, this.pageId = this.$opts.pageId, this.editContainer = this.$refs.editContainer, this.listContainer = this.$refs.listContainer, this.linksContainer = this.$refs.linksContainer, this.listPanel = this.$refs.listPanel, this.attachLinkButton = this.$refs.attachLinkButton, this.setupListeners()
    }
    setupListeners() {
        let t = this.reloadList.bind(this);
        this.container.addEventListener("dropzone-upload-success", t), this.container.addEventListener("ajax-form-success", t), this.container.addEventListener("sortable-list-sort", e => {
            this.updateOrder(e.detail.ids)
        }), this.container.addEventListener("event-emit-select-edit", e => {
            this.startEdit(e.detail.id)
        }), this.container.addEventListener("event-emit-select-edit-back", () => {
            this.stopEdit()
        }), this.container.addEventListener("event-emit-select-insert", e => {
            let i = e.target.closest("[data-drag-content]").getAttribute("data-drag-content"),
                r = JSON.parse(i);
            window.$events.emit("editor::insert", {
                html: r["text/html"],
                markdown: r["text/plain"]
            })
        }), this.attachLinkButton.addEventListener("click", () => {
            this.showSection("links")
        })
    }
    showSection(t) {
        let e = {
            links: this.linksContainer,
            edit: this.editContainer,
            list: this.listContainer
        };
        for (let [i, r] of Object.entries(e)) r.toggleAttribute("hidden", i !== t)
    }
    reloadList() {
        this.stopEdit(), window.$http.get(`/attachments/get/page/${this.pageId}`).then(t => {
            this.listPanel.innerHTML = t.data, window.$components.init(this.listPanel)
        })
    }
    updateOrder(t) {
        window.$http.put(`/attachments/sort/page/${this.pageId}`, {
            order: t
        }).then(e => {
            window.$events.emit("success", e.data.message)
        })
    }
    async startEdit(t) {
        this.showSection("edit"), De(this.editContainer);
        let e = await window.$http.get(`/attachments/edit/${t}`);
        this.editContainer.innerHTML = e.data, window.$components.init(this.editContainer)
    }
    stopEdit() {
        this.showSection("list")
    }
};
var pn = class extends g {
    setup() {
        this.container = this.$el, this.setupListeners()
    }
    setupListeners() {
        let t = e => e.key === "Control" || e.key === "Meta";
        window.addEventListener("keydown", e => {
            t(e) && this.addOpenQueryToLinks()
        }, {
            passive: !0
        }), window.addEventListener("keyup", e => {
            t(e) && this.removeOpenQueryFromLinks()
        }, {
            passive: !0
        })
    }
    addOpenQueryToLinks() {
        let t = this.container.querySelectorAll("a.attachment-file");
        for (let e of t) e.href.split("?")[1] !== "open=true" && (e.href += "?open=true", e.setAttribute("target", "_blank"))
    }
    removeOpenQueryFromLinks() {
        let t = this.container.querySelectorAll("a.attachment-file");
        for (let e of t) e.href = e.href.split("?")[0], e.removeAttribute("target")
    }
};
var Te, Cr, $e, Er, zt = class {
    constructor(t, e = null, i = null) {
        ot(this, Te);
        ot(this, $e);
        this.containers = [t], this.onEscape = e, this.onEnter = i, t.addEventListener("keydown", L(this, Te, Cr).bind(this))
    }
    shareHandlingToEl(t) {
        this.containers.push(t), t.addEventListener("keydown", L(this, Te, Cr).bind(this))
    }
    focusNext() {
        let t = L(this, $e, Er).call(this),
            i = t.indexOf(document.activeElement) + 1;
        i >= t.length && (i = 0), t[i].focus()
    }
    focusPrevious() {
        let t = L(this, $e, Er).call(this),
            i = t.indexOf(document.activeElement) - 1;
        i < 0 && (i = t.length - 1), t[i].focus()
    }
};
Te = new WeakSet, Cr = function(t) {
    t.target.matches("input") && (t.key === "ArrowRight" || t.key === "ArrowLeft") || (t.key === "ArrowDown" || t.key === "ArrowRight" ? (this.focusNext(), t.preventDefault()) : t.key === "ArrowUp" || t.key === "ArrowLeft" ? (this.focusPrevious(), t.preventDefault()) : t.key === "Escape" ? this.onEscape ? this.onEscape(t) : document.activeElement && document.activeElement.blur() : t.key === "Enter" && this.onEnter && this.onEnter(t))
}, $e = new WeakSet, Er = function() {
    let t = [],
        e = '[tabindex]:not([tabindex="-1"]),[href],button:not([tabindex="-1"],[disabled]),input:not([type=hidden])';
    for (let i of this.containers) t.push(...i.querySelectorAll(e));
    return t
};
var _r = {},
    fn = class extends g {
        setup() {
            this.parent = this.$el.parentElement, this.container = this.$el, this.type = this.$opts.type, this.url = this.$opts.url, this.input = this.$refs.input, this.list = this.$refs.list, this.lastPopulated = 0, this.setupListeners()
        }
        setupListeners() {
            new zt(this.list, () => {
                this.input.focus(), setTimeout(() => this.hideSuggestions(), 1)
            }, e => {
                e.preventDefault();
                let i = e.target.textContent;
                i && this.selectSuggestion(i)
            }).shareHandlingToEl(this.input), K(this.list, ".text-item", "click", (e, i) => {
                this.selectSuggestion(i.textContent)
            }), this.input.addEventListener("input", this.requestSuggestions.bind(this)), this.input.addEventListener("focus", this.requestSuggestions.bind(this)), this.input.addEventListener("blur", this.hideSuggestionsIfFocusedLost.bind(this)), this.input.addEventListener("keydown", e => {
                e.key === "Tab" && this.hideSuggestions()
            })
        }
        selectSuggestion(t) {
            this.input.value = t, this.lastPopulated = Date.now(), this.input.focus(), this.input.dispatchEvent(new Event("input", {
                bubbles: !0
            })), this.input.dispatchEvent(new Event("change", {
                bubbles: !0
            })), this.hideSuggestions()
        }
        async requestSuggestions() {
            if (Date.now() - this.lastPopulated < 50) return;
            let t = this.getNameFilterIfNeeded(),
                e = this.input.value.toLowerCase(),
                r = (await this.loadSuggestions(e, t)).filter(o => e === "" || o.toLowerCase().startsWith(e)).slice(0, 10);
            this.displaySuggestions(r)
        }
        getNameFilterIfNeeded() {
            return this.type !== "value" ? null : this.parent.querySelector("input").value
        }
        async loadSuggestions(t, e = null) {
            t = t.slice(0, 4);
            let i = {
                    search: t,
                    name: e
                },
                r = `${this.url}:${JSON.stringify(i)}`;
            if (_r[r]) return _r[r];
            let o = await window.$http.get(this.url, i);
            return _r[r] = o.data, o.data
        }
        displaySuggestions(t) {
            if (t.length === 0) {
                this.hideSuggestions();
                return
            }
            this.list.innerHTML = t.map(e => `<li><div tabindex="0" class="text-item">${ts(e)}</div></li>`).join(""), this.list.style.display = "block";
            for (let e of this.list.querySelectorAll(".text-item")) e.addEventListener("blur", this.hideSuggestionsIfFocusedLost.bind(this))
        }
        hideSuggestions() {
            this.list.style.display = "none"
        }
        hideSuggestionsIfFocusedLost(t) {
            this.container.contains(t.relatedTarget) || this.hideSuggestions()
        }
    };
var mn = class extends g {
    setup() {
        this.form = this.$el, this.form.submit()
    }
};
var gn = class extends g {
    setup() {
        if (this.button = this.$el, this.targetElem = document.getElementById("header"), this.showing = !1, this.breakPoint = 1200, document.body.classList.contains("flexbox")) {
            this.button.style.display = "none";
            return
        }
        this.button.addEventListener("click", this.scrollToTop.bind(this)), window.addEventListener("scroll", this.onPageScroll.bind(this))
    }
    onPageScroll() {
        let t = document.documentElement.scrollTop || document.body.scrollTop || 0;
        !this.showing && t > this.breakPoint ? (this.button.style.display = "block", this.showing = !0, setTimeout(() => {
            this.button.style.opacity = .4
        }, 1)) : this.showing && t < this.breakPoint && (this.button.style.opacity = 0, this.showing = !1, setTimeout(() => {
            this.button.style.display = "none"
        }, 500))
    }
    scrollToTop() {
        let t = this.targetElem.getBoundingClientRect().top,
            e = document.documentElement.scrollTop ? document.documentElement : document.body,
            i = 300,
            r = Date.now(),
            o = this.targetElem.getBoundingClientRect().top;

        function s() {
            let a = 1 - (Date.now() - r) / i,
                l = Math.abs(a * o);
            a > 0 ? (e.scrollTop = l, requestAnimationFrame(s.bind(this))) : e.scrollTop = t
        }
        requestAnimationFrame(s.bind(this))
    }
};

function is(n, t) {
    var e = Object.keys(n);
    if (Object.getOwnPropertySymbols) {
        var i = Object.getOwnPropertySymbols(n);
        t && (i = i.filter(function(r) {
            return Object.getOwnPropertyDescriptor(n, r).enumerable
        })), e.push.apply(e, i)
    }
    return e
}

function At(n) {
    for (var t = 1; t < arguments.length; t++) {
        var e = arguments[t] != null ? arguments[t] : {};
        t % 2 ? is(Object(e), !0).forEach(function(i) {
            ih(n, i, e[i])
        }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(n, Object.getOwnPropertyDescriptors(e)) : is(Object(e)).forEach(function(i) {
            Object.defineProperty(n, i, Object.getOwnPropertyDescriptor(e, i))
        })
    }
    return n
}

function Cn(n) {
    "@babel/helpers - typeof";
    return typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? Cn = function(t) {
        return typeof t
    } : Cn = function(t) {
        return t && typeof Symbol == "function" && t.constructor === Symbol && t !== Symbol.prototype ? "symbol" : typeof t
    }, Cn(n)
}

function ih(n, t, e) {
    return t in n ? Object.defineProperty(n, t, {
        value: e,
        enumerable: !0,
        configurable: !0,
        writable: !0
    }) : n[t] = e, n
}

function kt() {
    return kt = Object.assign || function(n) {
        for (var t = 1; t < arguments.length; t++) {
            var e = arguments[t];
            for (var i in e) Object.prototype.hasOwnProperty.call(e, i) && (n[i] = e[i])
        }
        return n
    }, kt.apply(this, arguments)
}

function rh(n, t) {
    if (n == null) return {};
    var e = {},
        i = Object.keys(n),
        r, o;
    for (o = 0; o < i.length; o++) r = i[o], !(t.indexOf(r) >= 0) && (e[r] = n[r]);
    return e
}

function oh(n, t) {
    if (n == null) return {};
    var e = rh(n, t),
        i, r;
    if (Object.getOwnPropertySymbols) {
        var o = Object.getOwnPropertySymbols(n);
        for (r = 0; r < o.length; r++) i = o[r], !(t.indexOf(i) >= 0) && Object.prototype.propertyIsEnumerable.call(n, i) && (e[i] = n[i])
    }
    return e
}

function sh(n) {
    return ah(n) || lh(n) || ch(n) || uh()
}

function ah(n) {
    if (Array.isArray(n)) return Br(n)
}

function lh(n) {
    if (typeof Symbol < "u" && n[Symbol.iterator] != null || n["@@iterator"] != null) return Array.from(n)
}

function ch(n, t) {
    if (n) {
        if (typeof n == "string") return Br(n, t);
        var e = Object.prototype.toString.call(n).slice(8, -1);
        if (e === "Object" && n.constructor && (e = n.constructor.name), e === "Map" || e === "Set") return Array.from(n);
        if (e === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(e)) return Br(n, t)
    }
}

function Br(n, t) {
    (t == null || t > n.length) && (t = n.length);
    for (var e = 0, i = new Array(t); e < t; e++) i[e] = n[e];
    return i
}

function uh() {
    throw new TypeError(`Invalid attempt to spread non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)
}
var hh = "1.15.0";

function It(n) {
    if (typeof window < "u" && window.navigator) return !!navigator.userAgent.match(n)
}
var Mt = It(/(?:Trident.*rv[ :]?11\.|msie|iemobile|Windows Phone)/i),
    je = It(/Edge/i),
    rs = It(/firefox/i),
    Re = It(/safari/i) && !It(/chrome/i) && !It(/android/i),
    fs = It(/iP(ad|od|hone)/i),
    ms = It(/chrome/i) && It(/android/i),
    gs = {
        capture: !1,
        passive: !1
    };

function O(n, t, e) {
    n.addEventListener(t, e, !Mt && gs)
}

function B(n, t, e) {
    n.removeEventListener(t, e, !Mt && gs)
}

function Dn(n, t) {
    if (t) {
        if (t[0] === ">" && (t = t.substring(1)), n) try {
            if (n.matches) return n.matches(t);
            if (n.msMatchesSelector) return n.msMatchesSelector(t);
            if (n.webkitMatchesSelector) return n.webkitMatchesSelector(t)
        } catch {
            return !1
        }
        return !1
    }
}

function dh(n) {
    return n.host && n !== document && n.host.nodeType ? n.host : n.parentNode
}

function xt(n, t, e, i) {
    if (n) {
        e = e || document;
        do {
            if (t != null && (t[0] === ">" ? n.parentNode === e && Dn(n, t) : Dn(n, t)) || i && n === e) return n;
            if (n === e) break
        } while (n = dh(n))
    }
    return null
}
var os = /\s+/g;

function Y(n, t, e) {
    if (n && t)
        if (n.classList) n.classList[e ? "add" : "remove"](t);
        else {
            var i = (" " + n.className + " ").replace(os, " ").replace(" " + t + " ", " ");
            n.className = (i + (e ? " " + t : "")).replace(os, " ")
        }
}

function A(n, t, e) {
    var i = n && n.style;
    if (i) {
        if (e === void 0) return document.defaultView && document.defaultView.getComputedStyle ? e = document.defaultView.getComputedStyle(n, "") : n.currentStyle && (e = n.currentStyle), t === void 0 ? e : e[t];
        !(t in i) && t.indexOf("webkit") === -1 && (t = "-webkit-" + t), i[t] = e + (typeof e == "string" ? "" : "px")
    }
}

function Xt(n, t) {
    var e = "";
    if (typeof n == "string") e = n;
    else
        do {
            var i = A(n, "transform");
            i && i !== "none" && (e = i + " " + e)
        } while (!t && (n = n.parentNode));
    var r = window.DOMMatrix || window.WebKitCSSMatrix || window.CSSMatrix || window.MSCSSMatrix;
    return r && new r(e)
}

function bs(n, t, e) {
    if (n) {
        var i = n.getElementsByTagName(t),
            r = 0,
            o = i.length;
        if (e)
            for (; r < o; r++) e(i[r], r);
        return i
    }
    return []
}

function St() {
    var n = document.scrollingElement;
    return n || document.documentElement
}

function V(n, t, e, i, r) {
    if (!(!n.getBoundingClientRect && n !== window)) {
        var o, s, a, l, c, u, h;
        if (n !== window && n.parentNode && n !== St() ? (o = n.getBoundingClientRect(), s = o.top, a = o.left, l = o.bottom, c = o.right, u = o.height, h = o.width) : (s = 0, a = 0, l = window.innerHeight, c = window.innerWidth, u = window.innerHeight, h = window.innerWidth), (t || e) && n !== window && (r = r || n.parentNode, !Mt))
            do
                if (r && r.getBoundingClientRect && (A(r, "transform") !== "none" || e && A(r, "position") !== "static")) {
                    var d = r.getBoundingClientRect();
                    s -= d.top + parseInt(A(r, "border-top-width")), a -= d.left + parseInt(A(r, "border-left-width")), l = s + o.height, c = a + o.width;
                    break
                } while (r = r.parentNode);
        if (i && n !== window) {
            var f = Xt(r || n),
                p = f && f.a,
                m = f && f.d;
            f && (s /= m, a /= p, h /= p, u /= m, l = s + u, c = a + h)
        }
        return {
            top: s,
            left: a,
            bottom: l,
            right: c,
            width: h,
            height: u
        }
    }
}

function ss(n, t, e) {
    for (var i = jt(n, !0), r = V(n)[t]; i;) {
        var o = V(i)[e],
            s = void 0;
        if (e === "top" || e === "left" ? s = r >= o : s = r <= o, !s) return i;
        if (i === St()) break;
        i = jt(i, !1)
    }
    return !1
}

function pe(n, t, e, i) {
    for (var r = 0, o = 0, s = n.children; o < s.length;) {
        if (s[o].style.display !== "none" && s[o] !== I.ghost && (i || s[o] !== I.dragged) && xt(s[o], e.draggable, n, !1)) {
            if (r === t) return s[o];
            r++
        }
        o++
    }
    return null
}

function zr(n, t) {
    for (var e = n.lastElementChild; e && (e === I.ghost || A(e, "display") === "none" || t && !Dn(e, t));) e = e.previousElementSibling;
    return e || null
}

function J(n, t) {
    var e = 0;
    if (!n || !n.parentNode) return -1;
    for (; n = n.previousElementSibling;) n.nodeName.toUpperCase() !== "TEMPLATE" && n !== I.clone && (!t || Dn(n, t)) && e++;
    return e
}

function as(n) {
    var t = 0,
        e = 0,
        i = St();
    if (n)
        do {
            var r = Xt(n),
                o = r.a,
                s = r.d;
            t += n.scrollLeft * o, e += n.scrollTop * s
        } while (n !== i && (n = n.parentNode));
    return [t, e]
}

function ph(n, t) {
    for (var e in n)
        if (n.hasOwnProperty(e)) {
            for (var i in t)
                if (t.hasOwnProperty(i) && t[i] === n[e][i]) return Number(e)
        } return -1
}

function jt(n, t) {
    if (!n || !n.getBoundingClientRect) return St();
    var e = n,
        i = !1;
    do
        if (e.clientWidth < e.scrollWidth || e.clientHeight < e.scrollHeight) {
            var r = A(e);
            if (e.clientWidth < e.scrollWidth && (r.overflowX == "auto" || r.overflowX == "scroll") || e.clientHeight < e.scrollHeight && (r.overflowY == "auto" || r.overflowY == "scroll")) {
                if (!e.getBoundingClientRect || e === document.body) return St();
                if (i || t) return e;
                i = !0
            }
        } while (e = e.parentNode);
    return St()
}

function fh(n, t) {
    if (n && t)
        for (var e in t) t.hasOwnProperty(e) && (n[e] = t[e]);
    return n
}

function Sr(n, t) {
    return Math.round(n.top) === Math.round(t.top) && Math.round(n.left) === Math.round(t.left) && Math.round(n.height) === Math.round(t.height) && Math.round(n.width) === Math.round(t.width)
}
var Ne;

function vs(n, t) {
    return function() {
        if (!Ne) {
            var e = arguments,
                i = this;
            e.length === 1 ? n.call(i, e[0]) : n.apply(i, e), Ne = setTimeout(function() {
                Ne = void 0
            }, t)
        }
    }
}

function mh() {
    clearTimeout(Ne), Ne = void 0
}

function ws(n, t, e) {
    n.scrollLeft += t, n.scrollTop += e
}

function Hr(n) {
    var t = window.Polymer,
        e = window.jQuery || window.Zepto;
    return t && t.dom ? t.dom(n).cloneNode(!0) : e ? e(n).clone(!0)[0] : n.cloneNode(!0)
}

function ls(n, t) {
    A(n, "position", "absolute"), A(n, "top", t.top), A(n, "left", t.left), A(n, "width", t.width), A(n, "height", t.height)
}

function Ar(n) {
    A(n, "position", ""), A(n, "top", ""), A(n, "left", ""), A(n, "width", ""), A(n, "height", "")
}
var it = "Sortable" + new Date().getTime();

function gh() {
    var n = [],
        t;
    return {
        captureAnimationState: function() {
            if (n = [], !!this.options.animation) {
                var i = [].slice.call(this.el.children);
                i.forEach(function(r) {
                    if (!(A(r, "display") === "none" || r === I.ghost)) {
                        n.push({
                            target: r,
                            rect: V(r)
                        });
                        var o = At({}, n[n.length - 1].rect);
                        if (r.thisAnimationDuration) {
                            var s = Xt(r, !0);
                            s && (o.top -= s.f, o.left -= s.e)
                        }
                        r.fromRect = o
                    }
                })
            }
        },
        addAnimationState: function(i) {
            n.push(i)
        },
        removeAnimationState: function(i) {
            n.splice(ph(n, {
                target: i
            }), 1)
        },
        animateAll: function(i) {
            var r = this;
            if (!this.options.animation) {
                clearTimeout(t), typeof i == "function" && i();
                return
            }
            var o = !1,
                s = 0;
            n.forEach(function(a) {
                var l = 0,
                    c = a.target,
                    u = c.fromRect,
                    h = V(c),
                    d = c.prevFromRect,
                    f = c.prevToRect,
                    p = a.rect,
                    m = Xt(c, !0);
                m && (h.top -= m.f, h.left -= m.e), c.toRect = h, c.thisAnimationDuration && Sr(d, h) && !Sr(u, h) && (p.top - h.top) / (p.left - h.left) === (u.top - h.top) / (u.left - h.left) && (l = vh(p, d, f, r.options)), Sr(h, u) || (c.prevFromRect = u, c.prevToRect = h, l || (l = r.options.animation), r.animate(c, p, h, l)), l && (o = !0, s = Math.max(s, l), clearTimeout(c.animationResetTimer), c.animationResetTimer = setTimeout(function() {
                    c.animationTime = 0, c.prevFromRect = null, c.fromRect = null, c.prevToRect = null, c.thisAnimationDuration = null
                }, l), c.thisAnimationDuration = l)
            }), clearTimeout(t), o ? t = setTimeout(function() {
                typeof i == "function" && i()
            }, s) : typeof i == "function" && i(), n = []
        },
        animate: function(i, r, o, s) {
            if (s) {
                A(i, "transition", ""), A(i, "transform", "");
                var a = Xt(this.el),
                    l = a && a.a,
                    c = a && a.d,
                    u = (r.left - o.left) / (l || 1),
                    h = (r.top - o.top) / (c || 1);
                i.animatingX = !!u, i.animatingY = !!h, A(i, "transform", "translate3d(" + u + "px," + h + "px,0)"), this.forRepaintDummy = bh(i), A(i, "transition", "transform " + s + "ms" + (this.options.easing ? " " + this.options.easing : "")), A(i, "transform", "translate3d(0,0,0)"), typeof i.animated == "number" && clearTimeout(i.animated), i.animated = setTimeout(function() {
                    A(i, "transition", ""), A(i, "transform", ""), i.animated = !1, i.animatingX = !1, i.animatingY = !1
                }, s)
            }
        }
    }
}

function bh(n) {
    return n.offsetWidth
}

function vh(n, t, e, i) {
    return Math.sqrt(Math.pow(t.top - n.top, 2) + Math.pow(t.left - n.left, 2)) / Math.sqrt(Math.pow(t.top - e.top, 2) + Math.pow(t.left - e.left, 2)) * i.animation
}
var le = [],
    Dr = {
        initializeByDefault: !0
    },
    Ve = {
        mount: function(t) {
            for (var e in Dr) Dr.hasOwnProperty(e) && !(e in t) && (t[e] = Dr[e]);
            le.forEach(function(i) {
                if (i.pluginName === t.pluginName) throw "Sortable: Cannot mount plugin ".concat(t.pluginName, " more than once")
            }), le.push(t)
        },
        pluginEvent: function(t, e, i) {
            var r = this;
            this.eventCanceled = !1, i.cancel = function() {
                r.eventCanceled = !0
            };
            var o = t + "Global";
            le.forEach(function(s) {
                e[s.pluginName] && (e[s.pluginName][o] && e[s.pluginName][o](At({
                    sortable: e
                }, i)), e.options[s.pluginName] && e[s.pluginName][t] && e[s.pluginName][t](At({
                    sortable: e
                }, i)))
            })
        },
        initializePlugins: function(t, e, i, r) {
            le.forEach(function(a) {
                var l = a.pluginName;
                if (!(!t.options[l] && !a.initializeByDefault)) {
                    var c = new a(t, e, t.options);
                    c.sortable = t, c.options = t.options, t[l] = c, kt(i, c.defaults)
                }
            });
            for (var o in t.options)
                if (t.options.hasOwnProperty(o)) {
                    var s = this.modifyOption(t, o, t.options[o]);
                    typeof s < "u" && (t.options[o] = s)
                }
        },
        getEventProperties: function(t, e) {
            var i = {};
            return le.forEach(function(r) {
                typeof r.eventProperties == "function" && kt(i, r.eventProperties.call(e[r.pluginName], t))
            }), i
        },
        modifyOption: function(t, e, i) {
            var r;
            return le.forEach(function(o) {
                t[o.pluginName] && o.optionListeners && typeof o.optionListeners[e] == "function" && (r = o.optionListeners[e].call(t[o.pluginName], i))
            }), r
        }
    };

function qe(n) {
    var t = n.sortable,
        e = n.rootEl,
        i = n.name,
        r = n.targetEl,
        o = n.cloneEl,
        s = n.toEl,
        a = n.fromEl,
        l = n.oldIndex,
        c = n.newIndex,
        u = n.oldDraggableIndex,
        h = n.newDraggableIndex,
        d = n.originalEvent,
        f = n.putSortable,
        p = n.extraEventProperties;
    if (t = t || e && e[it], !!t) {
        var m, w = t.options,
            v = "on" + i.charAt(0).toUpperCase() + i.substr(1);
        window.CustomEvent && !Mt && !je ? m = new CustomEvent(i, {
            bubbles: !0,
            cancelable: !0
        }) : (m = document.createEvent("Event"), m.initEvent(i, !0, !0)), m.to = s || e, m.from = a || e, m.item = r || e, m.clone = o, m.oldIndex = l, m.newIndex = c, m.oldDraggableIndex = u, m.newDraggableIndex = h, m.originalEvent = d, m.pullMode = f ? f.lastPutMode : void 0;
        var b = At(At({}, p), Ve.getEventProperties(i, t));
        for (var k in b) m[k] = b[k];
        e && e.dispatchEvent(m), w[v] && w[v].call(t, m)
    }
}
var wh = ["evt"],
    lt = function(t, e) {
        var i = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {},
            r = i.evt,
            o = oh(i, wh);
        Ve.pluginEvent.bind(I)(t, e, At({
            dragEl: C,
            parentEl: Z,
            ghostEl: q,
            rootEl: j,
            nextEl: Zt,
            lastDownEl: En,
            cloneEl: G,
            cloneHidden: Ut,
            dragStarted: Be,
            putSortable: tt,
            activeSortable: I.active,
            originalEvent: r,
            oldIndex: de,
            oldDraggableIndex: ze,
            newIndex: mt,
            newDraggableIndex: Ht,
            hideGhostForTarget: Cs,
            unhideGhostForTarget: Es,
            cloneNowHidden: function() {
                Ut = !0
            },
            cloneNowShown: function() {
                Ut = !1
            },
            dispatchSortableEvent: function(a) {
                st({
                    sortable: e,
                    name: a,
                    originalEvent: r
                })
            }
        }, o))
    };

function st(n) {
    qe(At({
        putSortable: tt,
        cloneEl: G,
        targetEl: C,
        rootEl: j,
        oldIndex: de,
        oldDraggableIndex: ze,
        newIndex: mt,
        newDraggableIndex: Ht
    }, n))
}
var C, Z, q, j, Zt, En, G, Ut, de, mt, ze, Ht, bn, tt, he = !1,
    Ln = !1,
    Tn = [],
    Gt, wt, Lr, Tr, cs, us, Be, ce, He, Ue = !1,
    vn = !1,
    _n, nt, $r = [],
    Pr = !1,
    $n = [],
    Mn = typeof document < "u",
    wn = fs,
    hs = je || Mt ? "cssFloat" : "float",
    yh = Mn && !ms && !fs && "draggable" in document.createElement("div"),
    ys = function() {
        if (Mn) {
            if (Mt) return !1;
            var n = document.createElement("x");
            return n.style.cssText = "pointer-events:auto", n.style.pointerEvents === "auto"
        }
    }(),
    xs = function(t, e) {
        var i = A(t),
            r = parseInt(i.width) - parseInt(i.paddingLeft) - parseInt(i.paddingRight) - parseInt(i.borderLeftWidth) - parseInt(i.borderRightWidth),
            o = pe(t, 0, e),
            s = pe(t, 1, e),
            a = o && A(o),
            l = s && A(s),
            c = a && parseInt(a.marginLeft) + parseInt(a.marginRight) + V(o).width,
            u = l && parseInt(l.marginLeft) + parseInt(l.marginRight) + V(s).width;
        if (i.display === "flex") return i.flexDirection === "column" || i.flexDirection === "column-reverse" ? "vertical" : "horizontal";
        if (i.display === "grid") return i.gridTemplateColumns.split(" ").length <= 1 ? "vertical" : "horizontal";
        if (o && a.float && a.float !== "none") {
            var h = a.float === "left" ? "left" : "right";
            return s && (l.clear === "both" || l.clear === h) ? "vertical" : "horizontal"
        }
        return o && (a.display === "block" || a.display === "flex" || a.display === "table" || a.display === "grid" || c >= r && i[hs] === "none" || s && i[hs] === "none" && c + u > r) ? "vertical" : "horizontal"
    },
    xh = function(t, e, i) {
        var r = i ? t.left : t.top,
            o = i ? t.right : t.bottom,
            s = i ? t.width : t.height,
            a = i ? e.left : e.top,
            l = i ? e.right : e.bottom,
            c = i ? e.width : e.height;
        return r === a || o === l || r + s / 2 === a + c / 2
    },
    kh = function(t, e) {
        var i;
        return Tn.some(function(r) {
            var o = r[it].options.emptyInsertThreshold;
            if (!(!o || zr(r))) {
                var s = V(r),
                    a = t >= s.left - o && t <= s.right + o,
                    l = e >= s.top - o && e <= s.bottom + o;
                if (a && l) return i = r
            }
        }), i
    },
    ks = function(t) {
        function e(o, s) {
            return function(a, l, c, u) {
                var h = a.options.group.name && l.options.group.name && a.options.group.name === l.options.group.name;
                if (o == null && (s || h)) return !0;
                if (o == null || o === !1) return !1;
                if (s && o === "clone") return o;
                if (typeof o == "function") return e(o(a, l, c, u), s)(a, l, c, u);
                var d = (s ? a : l).options.group.name;
                return o === !0 || typeof o == "string" && o === d || o.join && o.indexOf(d) > -1
            }
        }
        var i = {},
            r = t.group;
        (!r || Cn(r) != "object") && (r = {
            name: r
        }), i.name = r.name, i.checkPull = e(r.pull, !0), i.checkPut = e(r.put), i.revertClone = r.revertClone, t.group = i
    },
    Cs = function() {
        !ys && q && A(q, "display", "none")
    },
    Es = function() {
        !ys && q && A(q, "display", "")
    };
Mn && !ms && document.addEventListener("click", function(n) {
    if (Ln) return n.preventDefault(), n.stopPropagation && n.stopPropagation(), n.stopImmediatePropagation && n.stopImmediatePropagation(), Ln = !1, !1
}, !0);
var Kt = function(t) {
        if (C) {
            t = t.touches ? t.touches[0] : t;
            var e = kh(t.clientX, t.clientY);
            if (e) {
                var i = {};
                for (var r in t) t.hasOwnProperty(r) && (i[r] = t[r]);
                i.target = i.rootEl = e, i.preventDefault = void 0, i.stopPropagation = void 0, e[it]._onDragOver(i)
            }
        }
    },
    Ch = function(t) {
        C && C.parentNode[it]._isOutsideThisEl(t.target)
    };

function I(n, t) {
    if (!(n && n.nodeType && n.nodeType === 1)) throw "Sortable: `el` must be an HTMLElement, not ".concat({}.toString.call(n));
    this.el = n, this.options = t = kt({}, t), n[it] = this;
    var e = {
        group: null,
        sort: !0,
        disabled: !1,
        store: null,
        handle: null,
        draggable: /^[uo]l$/i.test(n.nodeName) ? ">li" : ">*",
        swapThreshold: 1,
        invertSwap: !1,
        invertedSwapThreshold: null,
        removeCloneOnHide: !0,
        direction: function() {
            return xs(n, this.options)
        },
        ghostClass: "sortable-ghost",
        chosenClass: "sortable-chosen",
        dragClass: "sortable-drag",
        ignore: "a, img",
        filter: null,
        preventOnFilter: !0,
        animation: 0,
        easing: null,
        setData: function(s, a) {
            s.setData("Text", a.textContent)
        },
        dropBubble: !1,
        dragoverBubble: !1,
        dataIdAttr: "data-id",
        delay: 0,
        delayOnTouchOnly: !1,
        touchStartThreshold: (Number.parseInt ? Number : window).parseInt(window.devicePixelRatio, 10) || 1,
        forceFallback: !1,
        fallbackClass: "sortable-fallback",
        fallbackOnBody: !1,
        fallbackTolerance: 0,
        fallbackOffset: {
            x: 0,
            y: 0
        },
        supportPointer: I.supportPointer !== !1 && "PointerEvent" in window && !Re,
        emptyInsertThreshold: 5
    };
    Ve.initializePlugins(this, n, e);
    for (var i in e) !(i in t) && (t[i] = e[i]);
    ks(t);
    for (var r in this) r.charAt(0) === "_" && typeof this[r] == "function" && (this[r] = this[r].bind(this));
    this.nativeDraggable = t.forceFallback ? !1 : yh, this.nativeDraggable && (this.options.touchStartThreshold = 1), t.supportPointer ? O(n, "pointerdown", this._onTapStart) : (O(n, "mousedown", this._onTapStart), O(n, "touchstart", this._onTapStart)), this.nativeDraggable && (O(n, "dragover", this), O(n, "dragenter", this)), Tn.push(this.el), t.store && t.store.get && this.sort(t.store.get(this) || []), kt(this, gh())
}
I.prototype = {
    constructor: I,
    _isOutsideThisEl: function(t) {
        !this.el.contains(t) && t !== this.el && (ce = null)
    },
    _getDirection: function(t, e) {
        return typeof this.options.direction == "function" ? this.options.direction.call(this, t, e, C) : this.options.direction
    },
    _onTapStart: function(t) {
        if (t.cancelable) {
            var e = this,
                i = this.el,
                r = this.options,
                o = r.preventOnFilter,
                s = t.type,
                a = t.touches && t.touches[0] || t.pointerType && t.pointerType === "touch" && t,
                l = (a || t).target,
                c = t.target.shadowRoot && (t.path && t.path[0] || t.composedPath && t.composedPath()[0]) || l,
                u = r.filter;
            if ($h(i), !C && !(/mousedown|pointerdown/.test(s) && t.button !== 0 || r.disabled) && !c.isContentEditable && !(!this.nativeDraggable && Re && l && l.tagName.toUpperCase() === "SELECT") && (l = xt(l, r.draggable, i, !1), !(l && l.animated) && En !== l)) {
                if (de = J(l), ze = J(l, r.draggable), typeof u == "function") {
                    if (u.call(this, t, l, this)) {
                        st({
                            sortable: e,
                            rootEl: c,
                            name: "filter",
                            targetEl: l,
                            toEl: i,
                            fromEl: i
                        }), lt("filter", e, {
                            evt: t
                        }), o && t.cancelable && t.preventDefault();
                        return
                    }
                } else if (u && (u = u.split(",").some(function(h) {
                        if (h = xt(c, h.trim(), i, !1), h) return st({
                            sortable: e,
                            rootEl: h,
                            name: "filter",
                            targetEl: l,
                            fromEl: i,
                            toEl: i
                        }), lt("filter", e, {
                            evt: t
                        }), !0
                    }), u)) {
                    o && t.cancelable && t.preventDefault();
                    return
                }
                r.handle && !xt(c, r.handle, i, !1) || this._prepareDragStart(t, a, l)
            }
        }
    },
    _prepareDragStart: function(t, e, i) {
        var r = this,
            o = r.el,
            s = r.options,
            a = o.ownerDocument,
            l;
        if (i && !C && i.parentNode === o) {
            var c = V(i);
            if (j = o, C = i, Z = C.parentNode, Zt = C.nextSibling, En = i, bn = s.group, I.dragged = C, Gt = {
                    target: C,
                    clientX: (e || t).clientX,
                    clientY: (e || t).clientY
                }, cs = Gt.clientX - c.left, us = Gt.clientY - c.top, this._lastX = (e || t).clientX, this._lastY = (e || t).clientY, C.style["will-change"] = "all", l = function() {
                    if (lt("delayEnded", r, {
                            evt: t
                        }), I.eventCanceled) {
                        r._onDrop();
                        return
                    }
                    r._disableDelayedDragEvents(), !rs && r.nativeDraggable && (C.draggable = !0), r._triggerDragStart(t, e), st({
                        sortable: r,
                        name: "choose",
                        originalEvent: t
                    }), Y(C, s.chosenClass, !0)
                }, s.ignore.split(",").forEach(function(u) {
                    bs(C, u.trim(), Ir)
                }), O(a, "dragover", Kt), O(a, "mousemove", Kt), O(a, "touchmove", Kt), O(a, "mouseup", r._onDrop), O(a, "touchend", r._onDrop), O(a, "touchcancel", r._onDrop), rs && this.nativeDraggable && (this.options.touchStartThreshold = 4, C.draggable = !0), lt("delayStart", this, {
                    evt: t
                }), s.delay && (!s.delayOnTouchOnly || e) && (!this.nativeDraggable || !(je || Mt))) {
                if (I.eventCanceled) {
                    this._onDrop();
                    return
                }
                O(a, "mouseup", r._disableDelayedDrag), O(a, "touchend", r._disableDelayedDrag), O(a, "touchcancel", r._disableDelayedDrag), O(a, "mousemove", r._delayedDragTouchMoveHandler), O(a, "touchmove", r._delayedDragTouchMoveHandler), s.supportPointer && O(a, "pointermove", r._delayedDragTouchMoveHandler), r._dragStartTimer = setTimeout(l, s.delay)
            } else l()
        }
    },
    _delayedDragTouchMoveHandler: function(t) {
        var e = t.touches ? t.touches[0] : t;
        Math.max(Math.abs(e.clientX - this._lastX), Math.abs(e.clientY - this._lastY)) >= Math.floor(this.options.touchStartThreshold / (this.nativeDraggable && window.devicePixelRatio || 1)) && this._disableDelayedDrag()
    },
    _disableDelayedDrag: function() {
        C && Ir(C), clearTimeout(this._dragStartTimer), this._disableDelayedDragEvents()
    },
    _disableDelayedDragEvents: function() {
        var t = this.el.ownerDocument;
        B(t, "mouseup", this._disableDelayedDrag), B(t, "touchend", this._disableDelayedDrag), B(t, "touchcancel", this._disableDelayedDrag), B(t, "mousemove", this._delayedDragTouchMoveHandler), B(t, "touchmove", this._delayedDragTouchMoveHandler), B(t, "pointermove", this._delayedDragTouchMoveHandler)
    },
    _triggerDragStart: function(t, e) {
        e = e || t.pointerType == "touch" && t, !this.nativeDraggable || e ? this.options.supportPointer ? O(document, "pointermove", this._onTouchMove) : e ? O(document, "touchmove", this._onTouchMove) : O(document, "mousemove", this._onTouchMove) : (O(C, "dragend", this), O(j, "dragstart", this._onDragStart));
        try {
            document.selection ? Sn(function() {
                document.selection.empty()
            }) : window.getSelection().removeAllRanges()
        } catch {}
    },
    _dragStarted: function(t, e) {
        if (he = !1, j && C) {
            lt("dragStarted", this, {
                evt: e
            }), this.nativeDraggable && O(document, "dragover", Ch);
            var i = this.options;
            !t && Y(C, i.dragClass, !1), Y(C, i.ghostClass, !0), I.active = this, t && this._appendGhost(), st({
                sortable: this,
                name: "start",
                originalEvent: e
            })
        } else this._nulling()
    },
    _emulateDragOver: function() {
        if (wt) {
            this._lastX = wt.clientX, this._lastY = wt.clientY, Cs();
            for (var t = document.elementFromPoint(wt.clientX, wt.clientY), e = t; t && t.shadowRoot && (t = t.shadowRoot.elementFromPoint(wt.clientX, wt.clientY), t !== e);) e = t;
            if (C.parentNode[it]._isOutsideThisEl(t), e)
                do {
                    if (e[it]) {
                        var i = void 0;
                        if (i = e[it]._onDragOver({
                                clientX: wt.clientX,
                                clientY: wt.clientY,
                                target: t,
                                rootEl: e
                            }), i && !this.options.dragoverBubble) break
                    }
                    t = e
                } while (e = e.parentNode);
            Es()
        }
    },
    _onTouchMove: function(t) {
        if (Gt) {
            var e = this.options,
                i = e.fallbackTolerance,
                r = e.fallbackOffset,
                o = t.touches ? t.touches[0] : t,
                s = q && Xt(q, !0),
                a = q && s && s.a,
                l = q && s && s.d,
                c = wn && nt && as(nt),
                u = (o.clientX - Gt.clientX + r.x) / (a || 1) + (c ? c[0] - $r[0] : 0) / (a || 1),
                h = (o.clientY - Gt.clientY + r.y) / (l || 1) + (c ? c[1] - $r[1] : 0) / (l || 1);
            if (!I.active && !he) {
                if (i && Math.max(Math.abs(o.clientX - this._lastX), Math.abs(o.clientY - this._lastY)) < i) return;
                this._onDragStart(t, !0)
            }
            if (q) {
                s ? (s.e += u - (Lr || 0), s.f += h - (Tr || 0)) : s = {
                    a: 1,
                    b: 0,
                    c: 0,
                    d: 1,
                    e: u,
                    f: h
                };
                var d = "matrix(".concat(s.a, ",").concat(s.b, ",").concat(s.c, ",").concat(s.d, ",").concat(s.e, ",").concat(s.f, ")");
                A(q, "webkitTransform", d), A(q, "mozTransform", d), A(q, "msTransform", d), A(q, "transform", d), Lr = u, Tr = h, wt = o
            }
            t.cancelable && t.preventDefault()
        }
    },
    _appendGhost: function() {
        if (!q) {
            var t = this.options.fallbackOnBody ? document.body : j,
                e = V(C, !0, wn, !0, t),
                i = this.options;
            if (wn) {
                for (nt = t; A(nt, "position") === "static" && A(nt, "transform") === "none" && nt !== document;) nt = nt.parentNode;
                nt !== document.body && nt !== document.documentElement ? (nt === document && (nt = St()), e.top += nt.scrollTop, e.left += nt.scrollLeft) : nt = St(), $r = as(nt)
            }
            q = C.cloneNode(!0), Y(q, i.ghostClass, !1), Y(q, i.fallbackClass, !0), Y(q, i.dragClass, !0), A(q, "transition", ""), A(q, "transform", ""), A(q, "box-sizing", "border-box"), A(q, "margin", 0), A(q, "top", e.top), A(q, "left", e.left), A(q, "width", e.width), A(q, "height", e.height), A(q, "opacity", "0.8"), A(q, "position", wn ? "absolute" : "fixed"), A(q, "zIndex", "100000"), A(q, "pointerEvents", "none"), I.ghost = q, t.appendChild(q), A(q, "transform-origin", cs / parseInt(q.style.width) * 100 + "% " + us / parseInt(q.style.height) * 100 + "%")
        }
    },
    _onDragStart: function(t, e) {
        var i = this,
            r = t.dataTransfer,
            o = i.options;
        if (lt("dragStart", this, {
                evt: t
            }), I.eventCanceled) {
            this._onDrop();
            return
        }
        lt("setupClone", this), I.eventCanceled || (G = Hr(C), G.removeAttribute("id"), G.draggable = !1, G.style["will-change"] = "", this._hideClone(), Y(G, this.options.chosenClass, !1), I.clone = G), i.cloneId = Sn(function() {
            lt("clone", i), !I.eventCanceled && (i.options.removeCloneOnHide || j.insertBefore(G, C), i._hideClone(), st({
                sortable: i,
                name: "clone"
            }))
        }), !e && Y(C, o.dragClass, !0), e ? (Ln = !0, i._loopId = setInterval(i._emulateDragOver, 50)) : (B(document, "mouseup", i._onDrop), B(document, "touchend", i._onDrop), B(document, "touchcancel", i._onDrop), r && (r.effectAllowed = "move", o.setData && o.setData.call(i, r, C)), O(document, "drop", i), A(C, "transform", "translateZ(0)")), he = !0, i._dragStartId = Sn(i._dragStarted.bind(i, e, t)), O(document, "selectstart", i), Be = !0, Re && A(document.body, "user-select", "none")
    },
    _onDragOver: function(t) {
        var e = this.el,
            i = t.target,
            r, o, s, a = this.options,
            l = a.group,
            c = I.active,
            u = bn === l,
            h = a.sort,
            d = tt || c,
            f, p = this,
            m = !1;
        if (Pr) return;

        function w(Rt, Au) {
            lt(Rt, p, At({
                evt: t,
                isOwner: u,
                axis: f ? "vertical" : "horizontal",
                revert: s,
                dragRect: r,
                targetRect: o,
                canSort: h,
                fromSortable: d,
                target: i,
                completed: b,
                onMove: function(jo, Du) {
                    return yn(j, e, C, r, jo, V(jo), t, Du)
                },
                changed: k
            }, Au))
        }

        function v() {
            w("dragOverAnimationCapture"), p.captureAnimationState(), p !== d && d.captureAnimationState()
        }

        function b(Rt) {
            return w("dragOverCompleted", {
                insertion: Rt
            }), Rt && (u ? c._hideClone() : c._showClone(p), p !== d && (Y(C, tt ? tt.options.ghostClass : c.options.ghostClass, !1), Y(C, a.ghostClass, !0)), tt !== p && p !== I.active ? tt = p : p === I.active && tt && (tt = null), d === p && (p._ignoreWhileAnimating = i), p.animateAll(function() {
                w("dragOverAnimationComplete"), p._ignoreWhileAnimating = null
            }), p !== d && (d.animateAll(), d._ignoreWhileAnimating = null)), (i === C && !C.animated || i === e && !i.animated) && (ce = null), !a.dragoverBubble && !t.rootEl && i !== document && (C.parentNode[it]._isOutsideThisEl(t.target), !Rt && Kt(t)), !a.dragoverBubble && t.stopPropagation && t.stopPropagation(), m = !0
        }

        function k() {
            mt = J(C), Ht = J(C, a.draggable), st({
                sortable: p,
                name: "change",
                toEl: e,
                newIndex: mt,
                newDraggableIndex: Ht,
                originalEvent: t
            })
        }
        if (t.preventDefault !== void 0 && t.cancelable && t.preventDefault(), i = xt(i, a.draggable, e, !0), w("dragOver"), I.eventCanceled) return m;
        if (C.contains(t.target) || i.animated && i.animatingX && i.animatingY || p._ignoreWhileAnimating === i) return b(!1);
        if (Ln = !1, c && !a.disabled && (u ? h || (s = Z !== j) : tt === this || (this.lastPutMode = bn.checkPull(this, c, C, t)) && l.checkPut(this, c, C, t))) {
            if (f = this._getDirection(t, i) === "vertical", r = V(C), w("dragOverValid"), I.eventCanceled) return m;
            if (s) return Z = j, v(), this._hideClone(), w("revert"), I.eventCanceled || (Zt ? j.insertBefore(C, Zt) : j.appendChild(C)), b(!0);
            var x = zr(e, a.draggable);
            if (!x || Ah(t, f, this) && !x.animated) {
                if (x === C) return b(!1);
                if (x && e === t.target && (i = x), i && (o = V(i)), yn(j, e, C, r, i, o, t, !!i) !== !1) return v(), x && x.nextSibling ? e.insertBefore(C, x.nextSibling) : e.appendChild(C), Z = e, k(), b(!0)
            } else if (x && Sh(t, f, this)) {
                var E = pe(e, 0, a, !0);
                if (E === C) return b(!1);
                if (i = E, o = V(i), yn(j, e, C, r, i, o, t, !1) !== !1) return v(), e.insertBefore(C, E), Z = e, k(), b(!0)
            } else if (i.parentNode === e) {
                o = V(i);
                var y = 0,
                    S, D = C.parentNode !== e,
                    M = !xh(C.animated && C.toRect || r, i.animated && i.toRect || o, f),
                    T = f ? "top" : "left",
                    P = ss(i, "top", "top") || ss(C, "top", "top"),
                    H = P ? P.scrollTop : void 0;
                ce !== i && (S = o[T], Ue = !1, vn = !M && a.invertSwap || D), y = Dh(t, i, o, f, M ? 1 : a.swapThreshold, a.invertedSwapThreshold == null ? a.swapThreshold : a.invertedSwapThreshold, vn, ce === i);
                var U;
                if (y !== 0) {
                    var et = J(C);
                    do et -= y, U = Z.children[et]; while (U && (A(U, "display") === "none" || U === q))
                }
                if (y === 0 || U === i) return b(!1);
                ce = i, He = y;
                var W = i.nextElementSibling,
                    $ = !1;
                $ = y === 1;
                var Ot = yn(j, e, C, r, i, o, t, $);
                if (Ot !== !1) return (Ot === 1 || Ot === -1) && ($ = Ot === 1), Pr = !0, setTimeout(_h, 30), v(), $ && !W ? e.appendChild(C) : i.parentNode.insertBefore(C, $ ? W : i), P && ws(P, 0, H - P.scrollTop), Z = C.parentNode, S !== void 0 && !vn && (_n = Math.abs(S - V(i)[T])), k(), b(!0)
            }
            if (e.contains(C)) return b(!1)
        }
        return !1
    },
    _ignoreWhileAnimating: null,
    _offMoveEvents: function() {
        B(document, "mousemove", this._onTouchMove), B(document, "touchmove", this._onTouchMove), B(document, "pointermove", this._onTouchMove), B(document, "dragover", Kt), B(document, "mousemove", Kt), B(document, "touchmove", Kt)
    },
    _offUpEvents: function() {
        var t = this.el.ownerDocument;
        B(t, "mouseup", this._onDrop), B(t, "touchend", this._onDrop), B(t, "pointerup", this._onDrop), B(t, "touchcancel", this._onDrop), B(document, "selectstart", this)
    },
    _onDrop: function(t) {
        var e = this.el,
            i = this.options;
        if (mt = J(C), Ht = J(C, i.draggable), lt("drop", this, {
                evt: t
            }), Z = C && C.parentNode, mt = J(C), Ht = J(C, i.draggable), I.eventCanceled) {
            this._nulling();
            return
        }
        he = !1, vn = !1, Ue = !1, clearInterval(this._loopId), clearTimeout(this._dragStartTimer), Or(this.cloneId), Or(this._dragStartId), this.nativeDraggable && (B(document, "drop", this), B(e, "dragstart", this._onDragStart)), this._offMoveEvents(), this._offUpEvents(), Re && A(document.body, "user-select", ""), A(C, "transform", ""), t && (Be && (t.cancelable && t.preventDefault(), !i.dropBubble && t.stopPropagation()), q && q.parentNode && q.parentNode.removeChild(q), (j === Z || tt && tt.lastPutMode !== "clone") && G && G.parentNode && G.parentNode.removeChild(G), C && (this.nativeDraggable && B(C, "dragend", this), Ir(C), C.style["will-change"] = "", Be && !he && Y(C, tt ? tt.options.ghostClass : this.options.ghostClass, !1), Y(C, this.options.chosenClass, !1), st({
            sortable: this,
            name: "unchoose",
            toEl: Z,
            newIndex: null,
            newDraggableIndex: null,
            originalEvent: t
        }), j !== Z ? (mt >= 0 && (st({
            rootEl: Z,
            name: "add",
            toEl: Z,
            fromEl: j,
            originalEvent: t
        }), st({
            sortable: this,
            name: "remove",
            toEl: Z,
            originalEvent: t
        }), st({
            rootEl: Z,
            name: "sort",
            toEl: Z,
            fromEl: j,
            originalEvent: t
        }), st({
            sortable: this,
            name: "sort",
            toEl: Z,
            originalEvent: t
        })), tt && tt.save()) : mt !== de && mt >= 0 && (st({
            sortable: this,
            name: "update",
            toEl: Z,
            originalEvent: t
        }), st({
            sortable: this,
            name: "sort",
            toEl: Z,
            originalEvent: t
        })), I.active && ((mt == null || mt === -1) && (mt = de, Ht = ze), st({
            sortable: this,
            name: "end",
            toEl: Z,
            originalEvent: t
        }), this.save()))), this._nulling()
    },
    _nulling: function() {
        lt("nulling", this), j = C = Z = q = Zt = G = En = Ut = Gt = wt = Be = mt = Ht = de = ze = ce = He = tt = bn = I.dragged = I.ghost = I.clone = I.active = null, $n.forEach(function(t) {
            t.checked = !0
        }), $n.length = Lr = Tr = 0
    },
    handleEvent: function(t) {
        switch (t.type) {
            case "drop":
            case "dragend":
                this._onDrop(t);
                break;
            case "dragenter":
            case "dragover":
                C && (this._onDragOver(t), Eh(t));
                break;
            case "selectstart":
                t.preventDefault();
                break
        }
    },
    toArray: function() {
        for (var t = [], e, i = this.el.children, r = 0, o = i.length, s = this.options; r < o; r++) e = i[r], xt(e, s.draggable, this.el, !1) && t.push(e.getAttribute(s.dataIdAttr) || Th(e));
        return t
    },
    sort: function(t, e) {
        var i = {},
            r = this.el;
        this.toArray().forEach(function(o, s) {
            var a = r.children[s];
            xt(a, this.options.draggable, r, !1) && (i[o] = a)
        }, this), e && this.captureAnimationState(), t.forEach(function(o) {
            i[o] && (r.removeChild(i[o]), r.appendChild(i[o]))
        }), e && this.animateAll()
    },
    save: function() {
        var t = this.options.store;
        t && t.set && t.set(this)
    },
    closest: function(t, e) {
        return xt(t, e || this.options.draggable, this.el, !1)
    },
    option: function(t, e) {
        var i = this.options;
        if (e === void 0) return i[t];
        var r = Ve.modifyOption(this, t, e);
        typeof r < "u" ? i[t] = r : i[t] = e, t === "group" && ks(i)
    },
    destroy: function() {
        lt("destroy", this);
        var t = this.el;
        t[it] = null, B(t, "mousedown", this._onTapStart), B(t, "touchstart", this._onTapStart), B(t, "pointerdown", this._onTapStart), this.nativeDraggable && (B(t, "dragover", this), B(t, "dragenter", this)), Array.prototype.forEach.call(t.querySelectorAll("[draggable]"), function(e) {
            e.removeAttribute("draggable")
        }), this._onDrop(), this._disableDelayedDragEvents(), Tn.splice(Tn.indexOf(this.el), 1), this.el = t = null
    },
    _hideClone: function() {
        if (!Ut) {
            if (lt("hideClone", this), I.eventCanceled) return;
            A(G, "display", "none"), this.options.removeCloneOnHide && G.parentNode && G.parentNode.removeChild(G), Ut = !0
        }
    },
    _showClone: function(t) {
        if (t.lastPutMode !== "clone") {
            this._hideClone();
            return
        }
        if (Ut) {
            if (lt("showClone", this), I.eventCanceled) return;
            C.parentNode == j && !this.options.group.revertClone ? j.insertBefore(G, C) : Zt ? j.insertBefore(G, Zt) : j.appendChild(G), this.options.group.revertClone && this.animate(C, G), A(G, "display", ""), Ut = !1
        }
    }
};

function Eh(n) {
    n.dataTransfer && (n.dataTransfer.dropEffect = "move"), n.cancelable && n.preventDefault()
}

function yn(n, t, e, i, r, o, s, a) {
    var l, c = n[it],
        u = c.options.onMove,
        h;
    return window.CustomEvent && !Mt && !je ? l = new CustomEvent("move", {
        bubbles: !0,
        cancelable: !0
    }) : (l = document.createEvent("Event"), l.initEvent("move", !0, !0)), l.to = t, l.from = n, l.dragged = e, l.draggedRect = i, l.related = r || t, l.relatedRect = o || V(t), l.willInsertAfter = a, l.originalEvent = s, n.dispatchEvent(l), u && (h = u.call(c, l, s)), h
}

function Ir(n) {
    n.draggable = !1
}

function _h() {
    Pr = !1
}

function Sh(n, t, e) {
    var i = V(pe(e.el, 0, e.options, !0)),
        r = 10;
    return t ? n.clientX < i.left - r || n.clientY < i.top && n.clientX < i.right : n.clientY < i.top - r || n.clientY < i.bottom && n.clientX < i.left
}

function Ah(n, t, e) {
    var i = V(zr(e.el, e.options.draggable)),
        r = 10;
    return t ? n.clientX > i.right + r || n.clientX <= i.right && n.clientY > i.bottom && n.clientX >= i.left : n.clientX > i.right && n.clientY > i.top || n.clientX <= i.right && n.clientY > i.bottom + r
}

function Dh(n, t, e, i, r, o, s, a) {
    var l = i ? n.clientY : n.clientX,
        c = i ? e.height : e.width,
        u = i ? e.top : e.left,
        h = i ? e.bottom : e.right,
        d = !1;
    if (!s) {
        if (a && _n < c * r) {
            if (!Ue && (He === 1 ? l > u + c * o / 2 : l < h - c * o / 2) && (Ue = !0), Ue) d = !0;
            else if (He === 1 ? l < u + _n : l > h - _n) return -He
        } else if (l > u + c * (1 - r) / 2 && l < h - c * (1 - r) / 2) return Lh(t)
    }
    return d = d || s, d && (l < u + c * o / 2 || l > h - c * o / 2) ? l > u + c / 2 ? 1 : -1 : 0
}

function Lh(n) {
    return J(C) < J(n) ? 1 : -1
}

function Th(n) {
    for (var t = n.tagName + n.className + n.src + n.href + n.textContent, e = t.length, i = 0; e--;) i += t.charCodeAt(e);
    return i.toString(36)
}

function $h(n) {
    $n.length = 0;
    for (var t = n.getElementsByTagName("input"), e = t.length; e--;) {
        var i = t[e];
        i.checked && $n.push(i)
    }
}

function Sn(n) {
    return setTimeout(n, 0)
}

function Or(n) {
    return clearTimeout(n)
}
Mn && O(document, "touchmove", function(n) {
    (I.active || he) && n.cancelable && n.preventDefault()
});
I.utils = {
    on: O,
    off: B,
    css: A,
    find: bs,
    is: function(t, e) {
        return !!xt(t, e, t, !1)
    },
    extend: fh,
    throttle: vs,
    closest: xt,
    toggleClass: Y,
    clone: Hr,
    index: J,
    nextTick: Sn,
    cancelNextTick: Or,
    detectDirection: xs,
    getChild: pe
};
I.get = function(n) {
    return n[it]
};
I.mount = function() {
    for (var n = arguments.length, t = new Array(n), e = 0; e < n; e++) t[e] = arguments[e];
    t[0].constructor === Array && (t = t[0]), t.forEach(function(i) {
        if (!i.prototype || !i.prototype.constructor) throw "Sortable: Mounted plugin must be a constructor function, not ".concat({}.toString.call(i));
        i.utils && (I.utils = At(At({}, I.utils), i.utils)), Ve.mount(i)
    })
};
I.create = function(n, t) {
    return new I(n, t)
};
I.version = hh;
var X = [],
    Pe, Rr, Nr = !1,
    Mr, Fr, In, Oe;

function Ih() {
    function n() {
        this.defaults = {
            scroll: !0,
            forceAutoScrollFallback: !1,
            scrollSensitivity: 30,
            scrollSpeed: 10,
            bubbleScroll: !0
        };
        for (var t in this) t.charAt(0) === "_" && typeof this[t] == "function" && (this[t] = this[t].bind(this))
    }
    return n.prototype = {
        dragStarted: function(e) {
            var i = e.originalEvent;
            this.sortable.nativeDraggable ? O(document, "dragover", this._handleAutoScroll) : this.options.supportPointer ? O(document, "pointermove", this._handleFallbackAutoScroll) : i.touches ? O(document, "touchmove", this._handleFallbackAutoScroll) : O(document, "mousemove", this._handleFallbackAutoScroll)
        },
        dragOverCompleted: function(e) {
            var i = e.originalEvent;
            !this.options.dragOverBubble && !i.rootEl && this._handleAutoScroll(i)
        },
        drop: function() {
            this.sortable.nativeDraggable ? B(document, "dragover", this._handleAutoScroll) : (B(document, "pointermove", this._handleFallbackAutoScroll), B(document, "touchmove", this._handleFallbackAutoScroll), B(document, "mousemove", this._handleFallbackAutoScroll)), ds(), An(), mh()
        },
        nulling: function() {
            In = Rr = Pe = Nr = Oe = Mr = Fr = null, X.length = 0
        },
        _handleFallbackAutoScroll: function(e) {
            this._handleAutoScroll(e, !0)
        },
        _handleAutoScroll: function(e, i) {
            var r = this,
                o = (e.touches ? e.touches[0] : e).clientX,
                s = (e.touches ? e.touches[0] : e).clientY,
                a = document.elementFromPoint(o, s);
            if (In = e, i || this.options.forceAutoScrollFallback || je || Mt || Re) {
                qr(e, this.options, a, i);
                var l = jt(a, !0);
                Nr && (!Oe || o !== Mr || s !== Fr) && (Oe && ds(), Oe = setInterval(function() {
                    var c = jt(document.elementFromPoint(o, s), !0);
                    c !== l && (l = c, An()), qr(e, r.options, c, i)
                }, 10), Mr = o, Fr = s)
            } else {
                if (!this.options.bubbleScroll || jt(a, !0) === St()) {
                    An();
                    return
                }
                qr(e, this.options, jt(a, !1), !1)
            }
        }
    }, kt(n, {
        pluginName: "scroll",
        initializeByDefault: !0
    })
}

function An() {
    X.forEach(function(n) {
        clearInterval(n.pid)
    }), X = []
}

function ds() {
    clearInterval(Oe)
}
var qr = vs(function(n, t, e, i) {
        if (t.scroll) {
            var r = (n.touches ? n.touches[0] : n).clientX,
                o = (n.touches ? n.touches[0] : n).clientY,
                s = t.scrollSensitivity,
                a = t.scrollSpeed,
                l = St(),
                c = !1,
                u;
            Rr !== e && (Rr = e, An(), Pe = t.scroll, u = t.scrollFn, Pe === !0 && (Pe = jt(e, !0)));
            var h = 0,
                d = Pe;
            do {
                var f = d,
                    p = V(f),
                    m = p.top,
                    w = p.bottom,
                    v = p.left,
                    b = p.right,
                    k = p.width,
                    x = p.height,
                    E = void 0,
                    y = void 0,
                    S = f.scrollWidth,
                    D = f.scrollHeight,
                    M = A(f),
                    T = f.scrollLeft,
                    P = f.scrollTop;
                f === l ? (E = k < S && (M.overflowX === "auto" || M.overflowX === "scroll" || M.overflowX === "visible"), y = x < D && (M.overflowY === "auto" || M.overflowY === "scroll" || M.overflowY === "visible")) : (E = k < S && (M.overflowX === "auto" || M.overflowX === "scroll"), y = x < D && (M.overflowY === "auto" || M.overflowY === "scroll"));
                var H = E && (Math.abs(b - r) <= s && T + k < S) - (Math.abs(v - r) <= s && !!T),
                    U = y && (Math.abs(w - o) <= s && P + x < D) - (Math.abs(m - o) <= s && !!P);
                if (!X[h])
                    for (var et = 0; et <= h; et++) X[et] || (X[et] = {});
                (X[h].vx != H || X[h].vy != U || X[h].el !== f) && (X[h].el = f, X[h].vx = H, X[h].vy = U, clearInterval(X[h].pid), (H != 0 || U != 0) && (c = !0, X[h].pid = setInterval(function() {
                    i && this.layer === 0 && I.active._onTouchMove(In);
                    var W = X[this.layer].vy ? X[this.layer].vy * a : 0,
                        $ = X[this.layer].vx ? X[this.layer].vx * a : 0;
                    typeof u == "function" && u.call(I.dragged.parentNode[it], $, W, n, In, X[this.layer].el) !== "continue" || ws(X[this.layer].el, $, W)
                }.bind({
                    layer: h
                }), 24))), h++
            } while (t.bubbleScroll && d !== l && (d = jt(d, !1)));
            Nr = c
        }
    }, 30),
    _s = function(t) {
        var e = t.originalEvent,
            i = t.putSortable,
            r = t.dragEl,
            o = t.activeSortable,
            s = t.dispatchSortableEvent,
            a = t.hideGhostForTarget,
            l = t.unhideGhostForTarget;
        if (e) {
            var c = i || o;
            a();
            var u = e.changedTouches && e.changedTouches.length ? e.changedTouches[0] : e,
                h = document.elementFromPoint(u.clientX, u.clientY);
            l(), c && !c.el.contains(h) && (s("spill"), this.onSpill({
                dragEl: r,
                putSortable: i
            }))
        }
    };

function Ur() {}
Ur.prototype = {
    startIndex: null,
    dragStart: function(t) {
        var e = t.oldDraggableIndex;
        this.startIndex = e
    },
    onSpill: function(t) {
        var e = t.dragEl,
            i = t.putSortable;
        this.sortable.captureAnimationState(), i && i.captureAnimationState();
        var r = pe(this.sortable.el, this.startIndex, this.options);
        r ? this.sortable.el.insertBefore(e, r) : this.sortable.el.appendChild(e), this.sortable.animateAll(), i && i.animateAll()
    },
    drop: _s
};
kt(Ur, {
    pluginName: "revertOnSpill"
});

function jr() {}
jr.prototype = {
    onSpill: function(t) {
        var e = t.dragEl,
            i = t.putSortable,
            r = i || this.sortable;
        r.captureAnimationState(), e.parentNode && e.parentNode.removeChild(e), r.animateAll()
    },
    drop: _s
};
kt(jr, {
    pluginName: "removeOnSpill"
});
var F = [],
    ft = [],
    Ie, yt, Me = !1,
    ct = !1,
    ue = !1,
    z, Fe, xn;

function Ss() {
    function n(t) {
        for (var e in this) e.charAt(0) === "_" && typeof this[e] == "function" && (this[e] = this[e].bind(this));
        t.options.avoidImplicitDeselect || (t.options.supportPointer ? O(document, "pointerup", this._deselectMultiDrag) : (O(document, "mouseup", this._deselectMultiDrag), O(document, "touchend", this._deselectMultiDrag))), O(document, "keydown", this._checkKeyDown), O(document, "keyup", this._checkKeyUp), this.defaults = {
            selectedClass: "sortable-selected",
            multiDragKey: null,
            avoidImplicitDeselect: !1,
            setData: function(r, o) {
                var s = "";
                F.length && yt === t ? F.forEach(function(a, l) {
                    s += (l ? ", " : "") + a.textContent
                }) : s = o.textContent, r.setData("Text", s)
            }
        }
    }
    return n.prototype = {
        multiDragKeyDown: !1,
        isMultiDrag: !1,
        delayStartGlobal: function(e) {
            var i = e.dragEl;
            z = i
        },
        delayEnded: function() {
            this.isMultiDrag = ~F.indexOf(z)
        },
        setupClone: function(e) {
            var i = e.sortable,
                r = e.cancel;
            if (this.isMultiDrag) {
                for (var o = 0; o < F.length; o++) ft.push(Hr(F[o])), ft[o].sortableIndex = F[o].sortableIndex, ft[o].draggable = !1, ft[o].style["will-change"] = "", Y(ft[o], this.options.selectedClass, !1), F[o] === z && Y(ft[o], this.options.chosenClass, !1);
                i._hideClone(), r()
            }
        },
        clone: function(e) {
            var i = e.sortable,
                r = e.rootEl,
                o = e.dispatchSortableEvent,
                s = e.cancel;
            this.isMultiDrag && (this.options.removeCloneOnHide || F.length && yt === i && (ps(!0, r), o("clone"), s()))
        },
        showClone: function(e) {
            var i = e.cloneNowShown,
                r = e.rootEl,
                o = e.cancel;
            this.isMultiDrag && (ps(!1, r), ft.forEach(function(s) {
                A(s, "display", "")
            }), i(), xn = !1, o())
        },
        hideClone: function(e) {
            var i = this,
                r = e.sortable,
                o = e.cloneNowHidden,
                s = e.cancel;
            this.isMultiDrag && (ft.forEach(function(a) {
                A(a, "display", "none"), i.options.removeCloneOnHide && a.parentNode && a.parentNode.removeChild(a)
            }), o(), xn = !0, s())
        },
        dragStartGlobal: function(e) {
            var i = e.sortable;
            !this.isMultiDrag && yt && yt.multiDrag._deselectMultiDrag(), F.forEach(function(r) {
                r.sortableIndex = J(r)
            }), F = F.sort(function(r, o) {
                return r.sortableIndex - o.sortableIndex
            }), ue = !0
        },
        dragStarted: function(e) {
            var i = this,
                r = e.sortable;
            if (this.isMultiDrag) {
                if (this.options.sort && (r.captureAnimationState(), this.options.animation)) {
                    F.forEach(function(s) {
                        s !== z && A(s, "position", "absolute")
                    });
                    var o = V(z, !1, !0, !0);
                    F.forEach(function(s) {
                        s !== z && ls(s, o)
                    }), ct = !0, Me = !0
                }
                r.animateAll(function() {
                    ct = !1, Me = !1, i.options.animation && F.forEach(function(s) {
                        Ar(s)
                    }), i.options.sort && kn()
                })
            }
        },
        dragOver: function(e) {
            var i = e.target,
                r = e.completed,
                o = e.cancel;
            ct && ~F.indexOf(i) && (r(!1), o())
        },
        revert: function(e) {
            var i = e.fromSortable,
                r = e.rootEl,
                o = e.sortable,
                s = e.dragRect;
            F.length > 1 && (F.forEach(function(a) {
                o.addAnimationState({
                    target: a,
                    rect: ct ? V(a) : s
                }), Ar(a), a.fromRect = s, i.removeAnimationState(a)
            }), ct = !1, Mh(!this.options.removeCloneOnHide, r))
        },
        dragOverCompleted: function(e) {
            var i = e.sortable,
                r = e.isOwner,
                o = e.insertion,
                s = e.activeSortable,
                a = e.parentEl,
                l = e.putSortable,
                c = this.options;
            if (o) {
                if (r && s._hideClone(), Me = !1, c.animation && F.length > 1 && (ct || !r && !s.options.sort && !l)) {
                    var u = V(z, !1, !0, !0);
                    F.forEach(function(d) {
                        d !== z && (ls(d, u), a.appendChild(d))
                    }), ct = !0
                }
                if (!r)
                    if (ct || kn(), F.length > 1) {
                        var h = xn;
                        s._showClone(i), s.options.animation && !xn && h && ft.forEach(function(d) {
                            s.addAnimationState({
                                target: d,
                                rect: Fe
                            }), d.fromRect = Fe, d.thisAnimationDuration = null
                        })
                    } else s._showClone(i)
            }
        },
        dragOverAnimationCapture: function(e) {
            var i = e.dragRect,
                r = e.isOwner,
                o = e.activeSortable;
            if (F.forEach(function(a) {
                    a.thisAnimationDuration = null
                }), o.options.animation && !r && o.multiDrag.isMultiDrag) {
                Fe = kt({}, i);
                var s = Xt(z, !0);
                Fe.top -= s.f, Fe.left -= s.e
            }
        },
        dragOverAnimationComplete: function() {
            ct && (ct = !1, kn())
        },
        drop: function(e) {
            var i = e.originalEvent,
                r = e.rootEl,
                o = e.parentEl,
                s = e.sortable,
                a = e.dispatchSortableEvent,
                l = e.oldIndex,
                c = e.putSortable,
                u = c || this.sortable;
            if (i) {
                var h = this.options,
                    d = o.children;
                if (!ue)
                    if (h.multiDragKey && !this.multiDragKeyDown && this._deselectMultiDrag(), Y(z, h.selectedClass, !~F.indexOf(z)), ~F.indexOf(z)) F.splice(F.indexOf(z), 1), Ie = null, qe({
                        sortable: s,
                        rootEl: r,
                        name: "deselect",
                        targetEl: z,
                        originalEvent: i
                    });
                    else {
                        if (F.push(z), qe({
                                sortable: s,
                                rootEl: r,
                                name: "select",
                                targetEl: z,
                                originalEvent: i
                            }), i.shiftKey && Ie && s.el.contains(Ie)) {
                            var f = J(Ie),
                                p = J(z);
                            if (~f && ~p && f !== p) {
                                var m, w;
                                for (p > f ? (w = f, m = p) : (w = p, m = f + 1); w < m; w++) ~F.indexOf(d[w]) || (Y(d[w], h.selectedClass, !0), F.push(d[w]), qe({
                                    sortable: s,
                                    rootEl: r,
                                    name: "select",
                                    targetEl: d[w],
                                    originalEvent: i
                                }))
                            }
                        } else Ie = z;
                        yt = u
                    } if (ue && this.isMultiDrag) {
                    if (ct = !1, (o[it].options.sort || o !== r) && F.length > 1) {
                        var v = V(z),
                            b = J(z, ":not(." + this.options.selectedClass + ")");
                        if (!Me && h.animation && (z.thisAnimationDuration = null), u.captureAnimationState(), !Me && (h.animation && (z.fromRect = v, F.forEach(function(x) {
                                if (x.thisAnimationDuration = null, x !== z) {
                                    var E = ct ? V(x) : v;
                                    x.fromRect = E, u.addAnimationState({
                                        target: x,
                                        rect: E
                                    })
                                }
                            })), kn(), F.forEach(function(x) {
                                d[b] ? o.insertBefore(x, d[b]) : o.appendChild(x), b++
                            }), l === J(z))) {
                            var k = !1;
                            F.forEach(function(x) {
                                if (x.sortableIndex !== J(x)) {
                                    k = !0;
                                    return
                                }
                            }), k && a("update")
                        }
                        F.forEach(function(x) {
                            Ar(x)
                        }), u.animateAll()
                    }
                    yt = u
                }(r === o || c && c.lastPutMode !== "clone") && ft.forEach(function(x) {
                    x.parentNode && x.parentNode.removeChild(x)
                })
            }
        },
        nullingGlobal: function() {
            this.isMultiDrag = ue = !1, ft.length = 0
        },
        destroyGlobal: function() {
            this._deselectMultiDrag(), B(document, "pointerup", this._deselectMultiDrag), B(document, "mouseup", this._deselectMultiDrag), B(document, "touchend", this._deselectMultiDrag), B(document, "keydown", this._checkKeyDown), B(document, "keyup", this._checkKeyUp)
        },
        _deselectMultiDrag: function(e) {
            if (!(typeof ue < "u" && ue) && yt === this.sortable && !(e && xt(e.target, this.options.draggable, this.sortable.el, !1)) && !(e && e.button !== 0))
                for (; F.length;) {
                    var i = F[0];
                    Y(i, this.options.selectedClass, !1), F.shift(), qe({
                        sortable: this.sortable,
                        rootEl: this.sortable.el,
                        name: "deselect",
                        targetEl: i,
                        originalEvent: e
                    })
                }
        },
        _checkKeyDown: function(e) {
            e.key === this.options.multiDragKey && (this.multiDragKeyDown = !0)
        },
        _checkKeyUp: function(e) {
            e.key === this.options.multiDragKey && (this.multiDragKeyDown = !1)
        }
    }, kt(n, {
        pluginName: "multiDrag",
        utils: {
            select: function(e) {
                var i = e.parentNode[it];
                !i || !i.options.multiDrag || ~F.indexOf(e) || (yt && yt !== i && (yt.multiDrag._deselectMultiDrag(), yt = i), Y(e, i.options.selectedClass, !0), F.push(e))
            },
            deselect: function(e) {
                var i = e.parentNode[it],
                    r = F.indexOf(e);
                !i || !i.options.multiDrag || !~r || (Y(e, i.options.selectedClass, !1), F.splice(r, 1))
            }
        },
        eventProperties: function() {
            var e = this,
                i = [],
                r = [];
            return F.forEach(function(o) {
                i.push({
                    multiDragElement: o,
                    index: o.sortableIndex
                });
                var s;
                ct && o !== z ? s = -1 : ct ? s = J(o, ":not(." + e.options.selectedClass + ")") : s = J(o), r.push({
                    multiDragElement: o,
                    index: s
                })
            }), {
                items: sh(F),
                clones: [].concat(ft),
                oldIndicies: i,
                newIndicies: r
            }
        },
        optionListeners: {
            multiDragKey: function(e) {
                return e = e.toLowerCase(), e === "ctrl" ? e = "Control" : e.length > 1 && (e = e.charAt(0).toUpperCase() + e.substr(1)), e
            }
        }
    })
}

function Mh(n, t) {
    F.forEach(function(e, i) {
        var r = t.children[e.sortableIndex + (n ? Number(i) : 0)];
        r ? t.insertBefore(e, r) : t.appendChild(e)
    })
}

function ps(n, t) {
    ft.forEach(function(e, i) {
        var r = t.children[e.sortableIndex + (n ? Number(i) : 0)];
        r ? t.insertBefore(e, r) : t.appendChild(e)
    })
}

function kn() {
    F.forEach(function(n) {
        n !== z && n.parentNode && n.parentNode.removeChild(n)
    })
}
I.mount(new Ih);
I.mount(jr, Ur);
var Yt = I;
var As = {
        name(n, t) {
            let e = n.getAttribute("data-name").trim().toLowerCase(),
                i = t.getAttribute("data-name").trim().toLowerCase();
            return e.localeCompare(i)
        },
        created(n, t) {
            let e = Number(n.getAttribute("data-created"));
            return Number(t.getAttribute("data-created")) - e
        },
        updated(n, t) {
            let e = Number(n.getAttribute("data-updated"));
            return Number(t.getAttribute("data-updated")) - e
        },
        chaptersFirst(n, t) {
            let e = n.getAttribute("data-type"),
                i = t.getAttribute("data-type");
            return e === i ? 0 : e === "chapter" ? -1 : 1
        },
        chaptersLast(n, t) {
            let e = n.getAttribute("data-type"),
                i = t.getAttribute("data-type");
            return e === i ? 0 : e === "chapter" ? 1 : -1
        }
    },
    Ds = {
        up: {
            active(n, t) {
                return !(n.previousElementSibling === null && !t)
            },
            run(n, t) {
                (n.previousElementSibling || t).insertAdjacentElement("beforebegin", n)
            }
        },
        down: {
            active(n, t) {
                return !(n.nextElementSibling === null && !t)
            },
            run(n, t) {
                (n.nextElementSibling || t).insertAdjacentElement("afterend", n)
            }
        },
        next_book: {
            active(n, t, e) {
                return e.nextElementSibling !== null
            },
            run(n, t, e) {
                e.nextElementSibling.querySelector("ul").prepend(n)
            }
        },
        prev_book: {
            active(n, t, e) {
                return e.previousElementSibling !== null
            },
            run(n, t, e) {
                e.previousElementSibling.querySelector("ul").appendChild(n)
            }
        },
        next_chapter: {
            active(n, t) {
                return n.dataset.type === "page" && this.getNextChapter(n, t)
            },
            run(n, t) {
                this.getNextChapter(n, t).querySelector("ul").prepend(n)
            },
            getNextChapter(n, t) {
                let e = t || n,
                    i = Array.from(e.parentElement.children),
                    r = i.indexOf(e);
                return i.slice(r + 1).find(o => o.dataset.type === "chapter")
            }
        },
        prev_chapter: {
            active(n, t) {
                return n.dataset.type === "page" && this.getPrevChapter(n, t)
            },
            run(n, t) {
                this.getPrevChapter(n, t).querySelector("ul").append(n)
            },
            getPrevChapter(n, t) {
                let e = t || n,
                    i = Array.from(e.parentElement.children),
                    r = i.indexOf(e);
                return i.slice(0, r).reverse().find(o => o.dataset.type === "chapter")
            }
        },
        book_end: {
            active(n, t) {
                return t || t === null && n.nextElementSibling
            },
            run(n, t, e) {
                e.querySelector("ul").append(n)
            }
        },
        book_start: {
            active(n, t) {
                return t || t === null && n.previousElementSibling
            },
            run(n, t, e) {
                e.querySelector("ul").prepend(n)
            }
        },
        before_chapter: {
            active(n, t) {
                return t
            },
            run(n, t) {
                t.insertAdjacentElement("beforebegin", n)
            }
        },
        after_chapter: {
            active(n, t) {
                return t
            },
            run(n, t) {
                t.insertAdjacentElement("afterend", n)
            }
        }
    },
    Fn = class extends g {
        setup() {
            this.container = this.$el, this.sortContainer = this.$refs.sortContainer, this.input = this.$refs.input, Yt.mount(new Ss);
            let t = this.container.querySelector(".sort-box");
            this.setupBookSortable(t), this.setupSortPresets(), this.setupMoveActions(), window.$events.listen("entity-select-change", this.bookSelect.bind(this))
        }
        setupMoveActions() {
            this.container.addEventListener("click", t => {
                if (t.target.matches("[data-move]")) {
                    let e = t.target.getAttribute("data-move"),
                        i = t.target.closest("[data-id]");
                    this.runSortAction(i, e)
                }
            }), this.updateMoveActionStateForAll()
        }
        setupSortPresets() {
            let t = "",
                e = !1,
                i = ["name", "created", "updated"];
            this.sortContainer.addEventListener("click", r => {
                let o = r.target.closest(".sort-box-options [data-sort]");
                if (!o) return;
                r.preventDefault();
                let s = o.closest(".sort-box").querySelectorAll("ul"),
                    a = o.getAttribute("data-sort");
                e = t === a ? !e : !1;
                let l = As[a];
                e && i.includes(a) && (l = function(u, h) {
                    return 0 - As[a](u, h)
                });
                for (let c of s) Array.from(c.children).filter(h => h.matches("li")).sort(l).forEach(h => {
                    c.appendChild(h)
                });
                t = a, this.updateMapInput()
            })
        }
        bookSelect(t) {
            if (this.container.querySelector(`[data-type="book"][data-id="${t.id}"]`) !== null) return;
            let i = `${t.link}/sort-item`;
            window.$http.get(i).then(r => {
                let o = _t(r.data);
                this.sortContainer.append(o), this.setupBookSortable(o), this.updateMoveActionStateForAll(), o.querySelector("summary").focus()
            })
        }
        setupBookSortable(t) {
            let e = Array.from(t.querySelectorAll(".sort-list, .sortable-page-sublist")),
                i = {
                    name: "book",
                    pull: ["book", "chapter"],
                    put: ["book", "chapter"]
                },
                r = {
                    name: "chapter",
                    pull: ["book", "chapter"],
                    put(o, s, a) {
                        return a.getAttribute("data-type") === "page"
                    }
                };
            for (let o of e) Yt.create(o, {
                group: o.classList.contains("sort-list") ? i : r,
                animation: 150,
                fallbackOnBody: !0,
                swapThreshold: .65,
                onSort: () => {
                    this.ensureNoNestedChapters(), this.updateMapInput(), this.updateMoveActionStateForAll()
                },
                dragClass: "bg-white",
                ghostClass: "primary-background-light",
                multiDrag: !0,
                multiDragKey: "Control",
                selectedClass: "sortable-selected"
            })
        }
        ensureNoNestedChapters() {
            let t = this.container.querySelectorAll('[data-type="chapter"] [data-type="chapter"]');
            for (let e of t) e.parentElement.closest('[data-type="chapter"]').insertAdjacentElement("afterend", e)
        }
        updateMapInput() {
            let t = this.buildEntityMap();
            this.input.value = JSON.stringify(t)
        }
        buildEntityMap() {
            let t = [],
                e = this.container.querySelectorAll(".sort-list");
            for (let i of e) {
                let r = i.closest('[data-type="book"]').getAttribute("data-id"),
                    o = Array.from(i.children).filter(s => s.matches('[data-type="page"], [data-type="chapter"]'));
                for (let s = 0; s < o.length; s++) this.addBookChildToMap(o[s], s, r, t)
            }
            return t
        }
        addBookChildToMap(t, e, i, r) {
            let o = t.getAttribute("data-type"),
                s = !1,
                a = t.getAttribute("data-id");
            r.push({
                id: a,
                sort: e,
                parentChapter: s,
                type: o,
                book: i
            });
            let l = t.querySelectorAll('[data-type="page"]');
            for (let c = 0; c < l.length; c++) r.push({
                id: l[c].getAttribute("data-id"),
                sort: c,
                parentChapter: a,
                type: "page",
                book: i
            })
        }
        runSortAction(t, e) {
            let i = t.parentElement.closest("li[data-id]"),
                r = t.parentElement.closest('[data-type="book"]');
            Ds[e].run(t, i, r), this.updateMapInput(), this.updateMoveActionStateForAll(), t.scrollIntoView({
                behavior: "smooth",
                block: "nearest"
            }), t.focus()
        }
        updateMoveActionState(t) {
            let e = t.parentElement.closest("li[data-id]"),
                i = t.parentElement.closest('[data-type="book"]');
            for (let [r, o] of Object.entries(Ds)) {
                let s = t.querySelector(`[data-move="${r}"]`);
                s.disabled = !o.active(t, e, i)
            }
        }
        updateMoveActionStateForAll() {
            let t = this.container.querySelectorAll('[data-type="chapter"],[data-type="page"]');
            for (let e of t) this.updateMoveActionState(e)
        }
    };
var qn = new WeakMap;

function We(n, t, e = 400, i = null) {
    let r = Object.keys(t);
    for (let s of r) n.style[s] = t[s][0];
    let o = () => {
        for (let s of r) n.style[s] = null;
        n.style.transition = null, n.removeEventListener("transitionend", o), qn.delete(n), i && i()
    };
    setTimeout(() => {
        n.style.transition = `all ease-in-out ${e}ms`;
        for (let s of r) n.style[s] = t[s][1];
        n.addEventListener("transitionend", o), qn.set(n, o)
    }, 15)
}

function Ge(n) {
    qn.has(n) && qn.get(n)()
}

function Ls(n, t = 400, e = null) {
    Ge(n), n.style.display = "block", We(n, {
        opacity: ["0", "1"]
    }, t, () => {
        e && e()
    })
}

function Ts(n, t = 400, e = null) {
    Ge(n), We(n, {
        opacity: ["1", "0"]
    }, t, () => {
        n.style.display = "none", e && e()
    })
}

function fe(n, t = 400) {
    Ge(n);
    let e = n.getBoundingClientRect().height,
        i = getComputedStyle(n),
        r = i.getPropertyValue("padding-top"),
        o = i.getPropertyValue("padding-bottom"),
        s = {
            maxHeight: [`${e}px`, "0px"],
            overflow: ["hidden", "hidden"],
            paddingTop: [r, "0px"],
            paddingBottom: [o, "0px"]
        };
    We(n, s, t, () => {
        n.style.display = "none"
    })
}

function me(n, t = 400) {
    Ge(n), n.style.display = "block";
    let e = n.getBoundingClientRect().height,
        i = getComputedStyle(n),
        r = i.getPropertyValue("padding-top"),
        o = i.getPropertyValue("padding-bottom"),
        s = {
            maxHeight: ["0px", `${e}px`],
            overflow: ["hidden", "hidden"],
            paddingTop: ["0px", r],
            paddingBottom: ["0px", o]
        };
    We(n, s, t)
}

function $s(n, t = 400) {
    let e = n.getBoundingClientRect().height,
        i = getComputedStyle(n),
        r = i.getPropertyValue("padding-top"),
        o = i.getPropertyValue("padding-bottom");
    return () => {
        Ge(n);
        let s = n.getBoundingClientRect().height,
            a = getComputedStyle(n),
            l = a.getPropertyValue("padding-top"),
            c = a.getPropertyValue("padding-bottom"),
            u = {
                height: [`${e}px`, `${s}px`],
                overflow: ["hidden", "hidden"],
                paddingTop: [r, l],
                paddingBottom: [o, c]
            };
        We(n, u, t)
    }
}
var Bn = class extends g {
    setup() {
        this.list = this.$refs.list, this.toggle = this.$refs.toggle, this.isOpen = this.toggle.classList.contains("open"), this.toggle.addEventListener("click", this.click.bind(this))
    }
    open() {
        this.toggle.classList.add("open"), this.toggle.setAttribute("aria-expanded", "true"), me(this.list, 180), this.isOpen = !0
    }
    close() {
        this.toggle.classList.remove("open"), this.toggle.setAttribute("aria-expanded", "false"), fe(this.list, 180), this.isOpen = !1
    }
    click(t) {
        t.preventDefault(), this.isOpen ? this.close() : this.open()
    }
};
var Pn = class extends g {
    constructor() {
        super(...arguments);
        at(this, "editor", null);
        at(this, "saveCallback", null);
        at(this, "cancelCallback", null);
        at(this, "history", {});
        at(this, "historyKey", "code_history")
    }
    setup() {
        this.container = this.$refs.container, this.popup = this.$el, this.editorInput = this.$refs.editor, this.languageButtons = this.$manyRefs.languageButton, this.languageOptionsContainer = this.$refs.languageOptionsContainer, this.saveButton = this.$refs.saveButton, this.languageInput = this.$refs.languageInput, this.historyDropDown = this.$refs.historyDropDown, this.historyList = this.$refs.historyList, this.favourites = new Set(this.$opts.favourites.split(",")), this.setupListeners(), this.setupFavourites()
    }
    setupListeners() {
        this.container.addEventListener("keydown", e => {
            e.ctrlKey && e.key === "Enter" && this.save()
        }), R(this.languageButtons, e => {
            let i = e.target.dataset.lang;
            this.languageInput.value = i, this.languageInputChange(i)
        }), se(this.languageInput, () => this.save()), this.languageInput.addEventListener("input", () => this.languageInputChange(this.languageInput.value)), R(this.saveButton, () => this.save()), K(this.historyList, "button", "click", (e, i) => {
            e.preventDefault();
            let r = i.dataset.time;
            this.editor && this.editor.setContent(this.history[r])
        })
    }
    setupFavourites() {
        for (let e of this.languageButtons) this.setupFavouritesForButton(e);
        this.sortLanguageList()
    }
    setupFavouritesForButton(e) {
        let i = e.dataset.lang,
            r = this.favourites.has(i);
        e.setAttribute("data-favourite", r ? "true" : "false"), K(e.parentElement, ".lang-option-favorite-toggle", "click", () => {
            r = !r, r ? this.favourites.add(i) : this.favourites.delete(i), e.setAttribute("data-favourite", r ? "true" : "false"), window.$http.patch("/preferences/update-code-language-favourite", {
                language: i,
                active: r
            }), this.sortLanguageList(), r && e.scrollIntoView({
                block: "center",
                behavior: "smooth"
            })
        })
    }
    sortLanguageList() {
        let e = this.languageButtons.sort((i, r) => {
            let o = i.dataset.favourite === "true",
                s = r.dataset.favourite === "true";
            return o && !s ? -1 : s && !o || i.dataset.lang > r.dataset.lang ? 1 : -1
        }).map(i => i.parentElement);
        for (let i of e) this.languageOptionsContainer.append(i)
    }
    save() {
        this.saveCallback && this.saveCallback(this.editor.getContent(), this.languageInput.value), this.hide()
    }
    async open(e, i, r, o) {
        this.languageInput.value = i, this.saveCallback = r, this.cancelCallback = o, await this.show(), this.languageInputChange(i), this.editor.setContent(e)
    }
    async show() {
        let e = await window.importVersioned("code");
        this.editor || (this.editor = e.popupEditor(this.editorInput, this.languageInput.value)), this.loadHistory(), this.getPopup().show(() => {
            this.editor.focus()
        }, () => {
            this.addHistory(), this.cancelCallback && this.cancelCallback()
        })
    }
    hide() {
        this.getPopup().hide(), this.addHistory()
    }
    getPopup() {
        return window.$components.firstOnElement(this.popup, "popup")
    }
    async updateEditorMode(e) {
        this.editor.setMode(e, this.editor.getContent())
    }
    languageInputChange(e) {
        this.updateEditorMode(e);
        let i = e.toLowerCase();
        for (let r of this.languageButtons) {
            let o = r.dataset.lang.toLowerCase().trim(),
                s = i === o;
            r.classList.toggle("active", s), s && r.scrollIntoView({
                block: "center",
                behavior: "smooth"
            })
        }
    }
    loadHistory() {
        this.history = JSON.parse(window.sessionStorage.getItem(this.historyKey) || "{}");
        let e = Object.keys(this.history).reverse();
        this.historyDropDown.classList.toggle("hidden", e.length === 0), this.historyList.innerHTML = e.map(i => {
            let r = new Date(parseInt(i, 10)).toLocaleTimeString();
            return `<li><button type="button" data-time="${i}" class="text-item">${r}</button></li>`
        }).join("")
    }
    addHistory() {
        if (!this.editor) return;
        let e = this.editor.getContent();
        if (!e) return;
        let i = Object.keys(this.history).pop();
        if (this.history[i] === e) return;
        this.history[String(Date.now())] = e;
        let r = JSON.stringify(this.history);
        window.sessionStorage.setItem(this.historyKey, r)
    }
};
var On = class extends g {
    setup() {
        let t = this.$el;
        t.querySelectorAll("pre").length > 0 && window.importVersioned("code").then(i => {
            i.highlightWithin(t)
        })
    }
};
var Rn = class extends g {
    async setup() {
        let {
            mode: t
        } = this.$opts;
        (await window.importVersioned("code")).inlineEditor(this.$el, t)
    }
};
var Nn = class extends g {
    setup() {
        this.container = this.$el, this.trigger = this.$refs.trigger, this.content = this.$refs.content, this.trigger && (this.trigger.addEventListener("click", this.toggle.bind(this)), this.openIfContainsError())
    }
    open() {
        this.container.classList.add("open"), this.trigger.setAttribute("aria-expanded", "true"), me(this.content, 300)
    }
    close() {
        this.container.classList.remove("open"), this.trigger.setAttribute("aria-expanded", "false"), fe(this.content, 300)
    }
    toggle() {
        this.container.classList.contains("open") ? this.close() : this.open()
    }
    openIfContainsError() {
        this.content.querySelector(".text-neg.text-small") && this.open()
    }
};
var zn = class extends g {
    setup() {
        this.container = this.$el, this.confirmButton = this.$refs.confirm, this.res = null, R(this.confirmButton, () => {
            this.sendResult(!0), this.getPopup().hide()
        })
    }
    show() {
        return this.getPopup().show(null, () => {
            this.sendResult(!1)
        }), new Promise(t => {
            this.res = t
        })
    }
    getPopup() {
        return window.$components.firstOnElement(this.container, "popup")
    }
    sendResult(t) {
        this.res && (this.res(t), this.res = null)
    }
};
var Hn = class extends g {
    setup() {
        this.container = this.$el, this.checkbox = this.container.querySelector("input[type=checkbox]"), this.display = this.container.querySelector('[role="checkbox"]'), this.checkbox.addEventListener("change", this.stateChange.bind(this)), this.container.addEventListener("keydown", this.onKeyDown.bind(this))
    }
    onKeyDown(t) {
        (t.key === " " || t.key === "Enter") && (t.preventDefault(), this.toggle())
    }
    toggle() {
        this.checkbox.checked = !this.checkbox.checked, this.checkbox.dispatchEvent(new Event("change")), this.stateChange()
    }
    stateChange() {
        let t = this.checkbox.checked ? "true" : "false";
        this.display.setAttribute("aria-checked", t)
    }
};
var Un = class extends g {
    setup() {
        this.container = this.$el, this.dealtWith = !1, this.container.addEventListener("toggle", this.onToggle.bind(this))
    }
    onToggle() {
        this.dealtWith || (this.container.querySelector("pre") && window.importVersioned("code").then(t => {
            t.highlightWithin(this.container)
        }), this.dealtWith = !0)
    }
};
var jn = class extends g {
    setup() {
        this.container = this.$el, this.menu = this.$refs.menu, this.toggle = this.$refs.toggle, this.moveMenu = this.$opts.moveMenu, this.bubbleEscapes = this.$opts.bubbleEscapes === "true", this.direction = document.dir === "rtl" ? "right" : "left", this.body = document.body, this.showing = !1, this.hide = this.hide.bind(this), this.setupListeners()
    }
    show(t = null) {
        this.hideAll(), this.menu.style.display = "block", this.menu.classList.add("anim", "menuIn"), this.toggle.setAttribute("aria-expanded", "true");
        let e = this.menu.getBoundingClientRect(),
            i = 0,
            r = this.toggle.getBoundingClientRect().height,
            o = e.bottom > window.innerHeight,
            s = this.container.getBoundingClientRect();
        if (this.moveMenu && (this.body.appendChild(this.menu), this.menu.style.position = "fixed", this.menu.style.width = `${e.width}px`, this.menu.style.left = `${e.left}px`, o ? i = window.innerHeight - e.top - r / 2 : i = e.top), o) {
            this.menu.style.top = "initial", this.menu.style.bottom = `${i}px`;
            let c = window.innerHeight - 40 - (window.innerHeight - s.bottom);
            this.menu.style.maxHeight = `${Math.floor(c)}px`
        } else {
            this.menu.style.top = `${i}px`, this.menu.style.bottom = "initial";
            let c = window.innerHeight - 40 - s.top;
            this.menu.style.maxHeight = `${Math.floor(c)}px`
        }
        this.menu.addEventListener("mouseleave", this.hide), window.addEventListener("click", c => {
            this.menu.contains(c.target) || this.hide()
        });
        let a = this.menu.querySelector("input");
        a !== null && a.focus(), this.showing = !0;
        let l = new Event("show");
        this.container.dispatchEvent(l), t && t.stopPropagation()
    }
    hideAll() {
        for (let t of window.$components.get("dropdown")) t.hide()
    }
    hide() {
        this.menu.style.display = "none", this.menu.classList.remove("anim", "menuIn"), this.toggle.setAttribute("aria-expanded", "false"), this.menu.style.top = "", this.menu.style.bottom = "", this.menu.style.maxHeight = "", this.moveMenu && (this.menu.style.position = "", this.menu.style[this.direction] = "", this.menu.style.width = "", this.menu.style.left = "", this.container.appendChild(this.menu)), this.showing = !1
    }
    setupListeners() {
        let t = new zt(this.container, e => {
            this.hide(), this.toggle.focus(), this.bubbleEscapes || e.stopPropagation()
        }, e => {
            e.target.nodeName === "INPUT" && (e.preventDefault(), e.stopPropagation()), this.hide()
        });
        this.moveMenu && t.shareHandlingToEl(this.menu), this.container.addEventListener("click", e => {
            Array.from(this.menu.querySelectorAll("a")).includes(e.target) && this.hide()
        }), R(this.toggle, e => {
            e.stopPropagation(), e.preventDefault(), this.show(e), e instanceof KeyboardEvent && t.focusNext()
        })
    }
};
var Vn = class extends g {
    setup() {
        this.elem = this.$el, this.searchInput = this.$refs.searchInput, this.loadingElem = this.$refs.loading, this.listContainerElem = this.$refs.listContainer, this.localSearchSelector = this.$opts.localSearchSelector, this.url = this.$opts.url, this.elem.addEventListener("show", this.onShow.bind(this)), this.searchInput.addEventListener("input", this.onSearch.bind(this)), this.runAjaxSearch = Nt(this.runAjaxSearch, 300, !1)
    }
    onShow() {
        this.loadList()
    }
    onSearch() {
        let t = this.searchInput.value.toLowerCase().trim();
        this.localSearchSelector ? this.runLocalSearch(t) : (this.toggleLoading(!0), this.listContainerElem.innerHTML = "", this.runAjaxSearch(t))
    }
    runAjaxSearch(t) {
        this.loadList(t)
    }
    runLocalSearch(t) {
        let e = this.listContainerElem.querySelectorAll(this.localSearchSelector);
        for (let i of e) {
            let r = !t || i.textContent.toLowerCase().includes(t);
            i.style.display = r ? "flex" : "none", i.classList.toggle("hidden", !r)
        }
    }
    async loadList(t = "") {
        this.listContainerElem.innerHTML = "", this.toggleLoading(!0);
        try {
            let e = await window.$http.get(this.getAjaxUrl(t)),
                i = $s(this.listContainerElem, 80);
            this.listContainerElem.innerHTML = e.data, i()
        } catch (e) {
            console.error(e)
        }
        this.toggleLoading(!1), this.localSearchSelector && this.onSearch()
    }
    getAjaxUrl(t = null) {
        if (!t) return this.url;
        let e = this.url.includes("?") ? "&" : "?";
        return `${this.url}${e}search=${encodeURIComponent(t)}`
    }
    toggleLoading(t = !1) {
        this.loadingElem.style.display = t ? "block" : "none"
    }
};
var Ft = class {
    constructor(t) {
        this.data = t
    }
    hasItems() {
        return !!this.data && !!this.data.types && this.data.types.length > 0
    }
    containsTabularData() {
        let t = this.data.getData("text/rtf");
        return t && t.includes("\\trowd")
    }
    getImages() {
        let {
            types: t
        } = this.data, e = [];
        for (let r of t)
            if (r.includes("image")) {
                let o = this.data.getData(r);
                e.push(o.getAsFile())
            } let i = this.getFiles().filter(r => r.type.includes("image"));
        return e.push(...i), e
    }
    getFiles() {
        let {
            files: t
        } = this.data;
        return [...t]
    }
};
async function Vr(n) {
    if (window.isSecureContext && navigator.clipboard) {
        await navigator.clipboard.writeText(n);
        return
    }
    let t = document.createElement("textarea");
    t.style = "position: absolute; left: -1000px; top: -1000px;", t.value = n, document.body.appendChild(t), t.select(), document.execCommand("copy"), document.body.removeChild(t)
}
var Wn = class extends g {
    setup() {
        this.container = this.$el, this.statusArea = this.$refs.statusArea, this.dropTarget = this.$refs.dropTarget, this.selectButtons = this.$manyRefs.selectButton || [], this.isActive = !0, this.url = this.$opts.url, this.method = (this.$opts.method || "post").toUpperCase(), this.successMessage = this.$opts.successMessage, this.errorMessage = this.$opts.errorMessage, this.uploadLimitMb = Number(this.$opts.uploadLimit), this.uploadLimitMessage = this.$opts.uploadLimitMessage, this.zoneText = this.$opts.zoneText, this.fileAcceptTypes = this.$opts.fileAccept, this.allowMultiple = this.$opts.allowMultiple === "true", this.setupListeners()
    }
    toggleActive(t) {
        this.isActive = t
    }
    setupListeners() {
        R(this.selectButtons, this.manualSelectHandler.bind(this)), this.setupDropTargetHandlers()
    }
    setupDropTargetHandlers() {
        let t = 0,
            e = () => {
                this.hideOverlay(), t = 0
            };
        this.dropTarget.addEventListener("dragenter", i => {
            i.preventDefault(), t += 1, t === 1 && this.isActive && this.showOverlay()
        }), this.dropTarget.addEventListener("dragover", i => {
            i.preventDefault()
        }), this.dropTarget.addEventListener("dragend", e), this.dropTarget.addEventListener("dragleave", () => {
            t -= 1, t === 0 && e()
        }), this.dropTarget.addEventListener("drop", i => {
            if (i.preventDefault(), e(), !this.isActive) return;
            let o = new Ft(i.dataTransfer).getFiles();
            for (let s of o) this.createUploadFromFile(s)
        })
    }
    manualSelectHandler() {
        let t = Et("input", {
            type: "file",
            style: "left: -400px; visibility: hidden; position: fixed;",
            accept: this.fileAcceptTypes,
            multiple: this.allowMultiple ? "" : null
        });
        this.container.append(t), t.click(), t.addEventListener("change", () => {
            for (let e of t.files) this.createUploadFromFile(e);
            t.remove()
        })
    }
    showOverlay() {
        if (!this.dropTarget.querySelector(".dropzone-overlay")) {
            let e = Et("div", {
                class: "dropzone-overlay"
            }, [this.zoneText]);
            this.dropTarget.append(e)
        }
    }
    hideOverlay() {
        let t = this.dropTarget.querySelector(".dropzone-overlay");
        t && t.remove()
    }
    createUploadFromFile(t) {
        let {
            dom: e,
            status: i,
            progress: r,
            dismiss: o
        } = this.createDomForFile(t);
        this.statusArea.append(e);
        let s = this,
            a = {
                file: t,
                dom: e,
                updateProgress(l) {
                    r.textContent = `${l}%`, r.style.width = `${l}%`
                },
                markError(l) {
                    i.setAttribute("data-status", "error"), i.textContent = l, Le(e), this.updateProgress(100)
                },
                markSuccess(l) {
                    i.setAttribute("data-status", "success"), i.textContent = l, Le(e), setTimeout(o, 2400), s.$emit("upload-success", {
                        name: t.name
                    })
                }
            };
        return t.size > this.uploadLimitMb * 1e6 ? (a.markError(this.uploadLimitMessage), a) : (this.startXhrForUpload(a), a)
    }
    startXhrForUpload(t) {
        let e = new FormData;
        e.append("file", t.file, t.file.name), this.method !== "POST" && e.append("_method", this.method);
        let i = this,
            r = window.$http.createXMLHttpRequest("POST", this.url, {
                error() {
                    t.markError(i.errorMessage)
                },
                readystatechange() {
                    if (this.readyState === XMLHttpRequest.DONE && this.status === 200) t.markSuccess(i.successMessage);
                    else if (this.readyState === XMLHttpRequest.DONE && this.status >= 400) {
                        let o = this.responseText,
                            s = o.startsWith("{") ? JSON.parse(o) : {
                                message: o
                            },
                            a = s?.message || s?.error || o;
                        t.markError(a)
                    }
                }
            });
        r.upload.addEventListener("progress", o => {
            let s = Math.min(Math.ceil(o.loaded / o.total * 100), 100);
            t.updateProgress(s)
        }), r.setRequestHeader("Accept", "application/json"), r.send(e)
    }
    createDomForFile(t) {
        let e = Et("img", {
                src: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M9.224 7.373a.924.924 0 0 0-.92.925l-.006 7.404c0 .509.412.925.921.925h5.557a.928.928 0 0 0 .926-.925v-5.553l-2.777-2.776Zm3.239 3.239V8.067l2.545 2.545z' style='fill:%23000;fill-opacity:.75'/%3E%3C/svg%3E"
            }),
            i = Et("div", {
                class: "dropzone-file-item-status"
            }, []),
            r = Et("div", {
                class: "dropzone-file-item-progress"
            }),
            o = Et("div", {
                class: "dropzone-file-item-image-wrap"
            }, [e]),
            s = Et("div", {
                class: "dropzone-file-item"
            }, [o, Et("div", {
                class: "dropzone-file-item-text-wrap"
            }, [Et("div", {
                class: "dropzone-file-item-label"
            }, [t.name]), ae(), i]), r]);
        t.type.startsWith("image/") && (e.src = URL.createObjectURL(t));
        let a = () => {
            s.classList.add("dismiss"), s.addEventListener("animationend", () => {
                s.remove()
            })
        };
        return s.addEventListener("click", a), {
            dom: s,
            progress: r,
            status: i,
            dismiss: a
        }
    }
};
var Gn = class extends g {
    setup() {
        this.container = this.$el, this.buttons = this.$manyRefs.tabButton, this.contentElements = this.$manyRefs.tabContent, this.toggleButton = this.$refs.toggle, this.editorWrapEl = this.container.closest(".page-editor"), this.setupListeners(), this.setActiveTab(this.contentElements[0].dataset.tabContent)
    }
    setupListeners() {
        this.toggleButton.addEventListener("click", () => this.toggle()), this.container.addEventListener("click", t => {
            let e = t.target.closest("button");
            if (this.buttons.includes(e)) {
                let i = e.dataset.tab;
                this.setActiveTab(i, !0)
            }
        })
    }
    toggle() {
        this.container.classList.toggle("open");
        let t = this.container.classList.contains("open");
        this.toggleButton.setAttribute("aria-expanded", t ? "true" : "false"), this.editorWrapEl.classList.toggle("toolbox-open", t)
    }
    setActiveTab(t, e = !1) {
        for (let i of this.buttons) i.classList.remove("active"), i.dataset.tab === t && i.classList.add("active");
        for (let i of this.contentElements) i.style.display = "none", i.dataset.tabContent === t && (i.style.display = "block");
        e && !this.container.classList.contains("open") && this.toggle()
    }
};
var Kn = class extends g {
    setup() {
        this.container = this.$el, this.entityType = this.$opts.entityType, this.everyoneInheritToggle = this.$refs.everyoneInherit, this.roleSelect = this.$refs.roleSelect, this.roleContainer = this.$refs.roleContainer, this.setupListeners()
    }
    setupListeners() {
        this.everyoneInheritToggle.addEventListener("change", t => {
            let e = t.target.checked,
                i = document.querySelectorAll('input[name^="permissions[0]["]');
            for (let r of i) r.disabled = e, r.checked = !1
        }), this.container.addEventListener("click", t => {
            let e = t.target.closest("button");
            e && e.dataset.roleId && this.removeRowOnButtonClick(e)
        }), this.roleSelect.addEventListener("change", () => {
            let t = this.roleSelect.value;
            t && this.addRoleRow(t)
        })
    }
    async addRoleRow(t) {
        this.roleSelect.disabled = !0;
        let e = this.roleSelect.querySelector(`option[value="${t}"]`);
        e && e.remove();
        let i = await window.$http.get(`/permissions/form-row/${this.entityType}/${t}`),
            r = _t(i.data);
        this.roleContainer.append(r), this.roleSelect.disabled = !1
    }
    removeRowOnButtonClick(t) {
        let e = t.closest(".item-list-row"),
            {
                roleId: i
            } = t.dataset,
            {
                roleName: r
            } = t.dataset,
            o = document.createElement("option");
        o.value = i, o.textContent = r, this.roleSelect.append(o), e.remove()
    }
};
var Zn = class extends g {
    setup() {
        this.entityId = this.$opts.entityId, this.entityType = this.$opts.entityType, this.contentView = this.$refs.contentView, this.searchView = this.$refs.searchView, this.searchResults = this.$refs.searchResults, this.searchInput = this.$refs.searchInput, this.searchForm = this.$refs.searchForm, this.clearButton = this.$refs.clearButton, this.loadingBlock = this.$refs.loadingBlock, this.setupListeners()
    }
    setupListeners() {
        this.searchInput.addEventListener("change", this.runSearch.bind(this)), this.searchForm.addEventListener("submit", t => {
            t.preventDefault(), this.runSearch()
        }), R(this.clearButton, this.clearSearch.bind(this))
    }
    runSearch() {
        let t = this.searchInput.value.trim();
        if (t.length === 0) {
            this.clearSearch();
            return
        }
        this.searchView.classList.remove("hidden"), this.contentView.classList.add("hidden"), this.loadingBlock.classList.remove("hidden");
        let e = window.baseUrl(`/search/${this.entityType}/${this.entityId}`);
        window.$http.get(e, {
            term: t
        }).then(i => {
            this.searchResults.innerHTML = i.data
        }).catch(console.error).then(() => {
            this.loadingBlock.classList.add("hidden")
        })
    }
    clearSearch() {
        this.searchView.classList.add("hidden"), this.contentView.classList.remove("hidden"), this.loadingBlock.classList.add("hidden"), this.searchInput.value = ""
    }
};
var Xn = class extends g {
    setup() {
        this.elem = this.$el, this.entityTypes = this.$opts.entityTypes || "page,book,chapter", this.entityPermission = this.$opts.entityPermission || "view", this.input = this.$refs.input, this.searchInput = this.$refs.search, this.loading = this.$refs.loading, this.resultsContainer = this.$refs.results, this.search = "", this.lastClick = 0, this.selectedItemData = null, this.setupListeners(), this.showLoading(), this.initialLoad()
    }
    setupListeners() {
        this.elem.addEventListener("click", this.onClick.bind(this));
        let t = 0;
        this.searchInput.addEventListener("input", () => {
            t = Date.now(), this.showLoading(), setTimeout(() => {
                Date.now() - t < 199 || this.searchEntities(this.searchInput.value)
            }, 200)
        }), this.searchInput.addEventListener("keydown", e => {
            e.keyCode === 13 && e.preventDefault()
        }), K(this.$el, "[data-entity-type]", "keydown", e => {
            if (e.ctrlKey && e.code === "Enter") {
                let i = this.$el.closest("form");
                if (i) {
                    i.submit(), e.preventDefault();
                    return
                }
            }
            e.code === "ArrowDown" && this.focusAdjacent(!0), e.code === "ArrowUp" && this.focusAdjacent(!1)
        }), this.searchInput.addEventListener("keydown", e => {
            e.code === "ArrowDown" && this.focusAdjacent(!0)
        })
    }
    focusAdjacent(t = !0) {
        let e = Array.from(this.resultsContainer.querySelectorAll("[data-entity-type]")),
            i = e.indexOf(document.activeElement),
            r = e[i + (t ? 1 : -1)] || e[0];
        r && r.focus()
    }
    reset() {
        this.searchInput.value = "", this.showLoading(), this.initialLoad()
    }
    focusSearch() {
        this.searchInput.focus()
    }
    searchText(t) {
        this.searchInput.value = t, this.searchEntities(t)
    }
    showLoading() {
        this.loading.style.display = "block", this.resultsContainer.style.display = "none"
    }
    hideLoading() {
        this.loading.style.display = "none", this.resultsContainer.style.display = "block"
    }
    initialLoad() {
        window.$http.get(this.searchUrl()).then(t => {
            this.resultsContainer.innerHTML = t.data, this.hideLoading()
        })
    }
    searchUrl() {
        return `/search/entity-selector?types=${encodeURIComponent(this.entityTypes)}&permission=${encodeURIComponent(this.entityPermission)}`
    }
    searchEntities(t) {
        this.input.value = "";
        let e = `${this.searchUrl()}&term=${encodeURIComponent(t)}`;
        window.$http.get(e).then(i => {
            this.resultsContainer.innerHTML = i.data, this.hideLoading()
        })
    }
    isDoubleClick() {
        let t = Date.now(),
            e = t - this.lastClick < 300;
        return this.lastClick = t, e
    }
    onClick(t) {
        let e = t.target.closest("[data-entity-type]");
        e && (t.preventDefault(), t.stopPropagation(), this.selectItem(e))
    }
    selectItem(t) {
        let e = this.isDoubleClick(),
            i = t.getAttribute("data-entity-type"),
            r = t.getAttribute("data-entity-id"),
            o = !t.classList.contains("selected") || e;
        this.unselectAll(), this.input.value = o ? `${i}:${r}` : "";
        let s = t.getAttribute("href"),
            a = t.querySelector(".entity-list-item-name").textContent,
            l = {
                id: Number(r),
                name: a,
                link: s
            };
        o ? (t.classList.add("selected"), this.selectedItemData = l) : window.$events.emit("entity-select-change", null), !(!e && !o) && (e && this.confirmSelection(l), o && window.$events.emit("entity-select-change", l))
    }
    confirmSelection(t) {
        window.$events.emit("entity-select-confirm", t)
    }
    unselectAll() {
        let t = this.elem.querySelectorAll(".selected");
        for (let e of t) e.classList.remove("selected", "primary-background");
        this.selectedItemData = null
    }
};
var Yn = class extends g {
    setup() {
        this.container = this.$el, this.selectButton = this.$refs.select, this.selectorEl = this.$refs.selector, this.callback = null, this.selection = null, this.selectButton.addEventListener("click", this.onSelectButtonClick.bind(this)), window.$events.listen("entity-select-change", this.onSelectionChange.bind(this)), window.$events.listen("entity-select-confirm", this.handleConfirmedSelection.bind(this))
    }
    show(t, e = "") {
        this.callback = t, this.getPopup().show(), e && this.getSelector().searchText(e), this.getSelector().focusSearch()
    }
    hide() {
        this.getPopup().hide()
    }
    getPopup() {
        return window.$components.firstOnElement(this.container, "popup")
    }
    getSelector() {
        return window.$components.firstOnElement(this.selectorEl, "entity-selector")
    }
    onSelectButtonClick() {
        this.handleConfirmedSelection(this.selection)
    }
    onSelectionChange(t) {
        this.selection = t, t === null ? this.selectButton.setAttribute("disabled", "true") : this.selectButton.removeAttribute("disabled")
    }
    handleConfirmedSelection(t) {
        this.hide(), this.getSelector().reset(), this.callback && t && this.callback(t)
    }
};
var Jn = class extends g {
    setup() {
        this.container = this.$el, this.name = this.$opts.name, R(this.$el, () => {
            this.$emit(this.name, this.$opts)
        })
    }
};
var Qn = class extends g {
    setup() {
        this.targetSelector = this.$opts.targetSelector, this.isOpen = this.$opts.isOpen === "true", this.updateEndpoint = this.$opts.updateEndpoint, this.$el.addEventListener("click", this.click.bind(this))
    }
    open(t) {
        me(t, 200)
    }
    close(t) {
        fe(t, 200)
    }
    click(t) {
        t.preventDefault();
        let e = document.querySelectorAll(this.targetSelector);
        for (let i of e)(this.isOpen ? this.close : this.open)(i);
        this.isOpen = !this.isOpen, this.updateSystemAjax(this.isOpen)
    }
    updateSystemAjax(t) {
        window.$http.patch(this.updateEndpoint, {
            expand: t ? "true" : "false"
        })
    }
};
var ti = class extends g {
    setup() {
        this.container = this.$el, this.input = this.$refs.input, this.suggestions = this.$refs.suggestions, this.suggestionResultsWrap = this.$refs.suggestionResults, this.loadingWrap = this.$refs.loading, this.button = this.$refs.button, this.setupListeners()
    }
    setupListeners() {
        let t = Nt(this.updateSuggestions.bind(this), 200, !1);
        this.input.addEventListener("input", () => {
            let {
                value: e
            } = this.input;
            e.length > 0 ? (this.loadingWrap.style.display = "block", this.suggestionResultsWrap.style.opacity = "0.5", t(e)) : this.hideSuggestions()
        }), this.input.addEventListener("dblclick", () => {
            this.input.setAttribute("autocomplete", "on"), this.button.focus(), this.input.focus()
        }), new zt(this.container, () => {
            this.hideSuggestions()
        })
    }
    async updateSuggestions(t) {
        let {
            data: e
        } = await window.$http.get("/search/suggest", {
            term: t
        });
        if (!this.input.value) return;
        let i = _t(e);
        this.suggestionResultsWrap.innerHTML = "", this.suggestionResultsWrap.style.opacity = "1", this.loadingWrap.style.display = "none", this.suggestionResultsWrap.append(i), this.container.classList.contains("search-active") || this.showSuggestions()
    }
    showSuggestions() {
        this.container.classList.add("search-active"), window.requestAnimationFrame(() => {
            this.suggestions.classList.add("search-suggestions-animation")
        })
    }
    hideSuggestions() {
        this.container.classList.remove("search-active"), this.suggestions.classList.remove("search-suggestions-animation"), this.suggestionResultsWrap.innerHTML = ""
    }
};
var ei = class extends g {
    setup() {
        this.elem = this.$el, this.toggleButton = this.$refs.toggle, this.menu = this.$refs.menu, this.open = !1, this.toggleButton.addEventListener("click", this.onToggle.bind(this)), this.onWindowClick = this.onWindowClick.bind(this), this.onKeyDown = this.onKeyDown.bind(this)
    }
    onToggle(t) {
        this.open = !this.open, this.menu.classList.toggle("show", this.open), this.toggleButton.setAttribute("aria-expanded", this.open ? "true" : "false"), this.open ? (this.elem.addEventListener("keydown", this.onKeyDown), window.addEventListener("click", this.onWindowClick)) : (this.elem.removeEventListener("keydown", this.onKeyDown), window.removeEventListener("click", this.onWindowClick)), t.stopPropagation()
    }
    onKeyDown(t) {
        t.code === "Escape" && this.onToggle(t)
    }
    onWindowClick(t) {
        this.onToggle(t)
    }
};
var ni = class extends g {
    setup() {
        this.uploadedTo = this.$opts.uploadedTo, this.container = this.$el, this.popupEl = this.$refs.popup, this.searchForm = this.$refs.searchForm, this.searchInput = this.$refs.searchInput, this.cancelSearch = this.$refs.cancelSearch, this.listContainer = this.$refs.listContainer, this.filterTabs = this.$manyRefs.filterTabs, this.selectButton = this.$refs.selectButton, this.uploadButton = this.$refs.uploadButton, this.uploadHint = this.$refs.uploadHint, this.formContainer = this.$refs.formContainer, this.formContainerPlaceholder = this.$refs.formContainerPlaceholder, this.dropzoneContainer = this.$refs.dropzoneContainer, this.loadMore = this.$refs.loadMore, this.type = "gallery", this.lastSelected = {}, this.lastSelectedTime = 0, this.callback = null, this.resetState = () => {
            this.hasData = !1, this.page = 1, this.filter = "all"
        }, this.resetState(), this.setupListeners()
    }
    setupListeners() {
        R(this.filterTabs, i => {
            this.resetAll(), this.filter = i.target.dataset.filter, this.setActiveFilterTab(this.filter), this.loadGallery()
        }), this.searchForm.addEventListener("submit", i => {
            this.resetListView(), this.loadGallery(), this.cancelSearch.toggleAttribute("hidden", !this.searchInput.value), i.preventDefault()
        }), R(this.cancelSearch, () => {
            this.resetListView(), this.resetSearchView(), this.loadGallery()
        }), K(this.container, ".load-more button", "click", this.runLoadMore.bind(this)), this.listContainer.addEventListener("event-emit-select-image", this.onImageSelectEvent.bind(this)), this.listContainer.addEventListener("error", i => {
            i.target.src = window.baseUrl("loading_error.png")
        }, !0), R(this.selectButton, () => {
            this.callback && this.callback(this.lastSelected), this.hide()
        }), K(this.formContainer, "#image-manager-delete", "click", () => {
            this.lastSelected && this.loadImageEditForm(this.lastSelected.id, !0)
        }), K(this.formContainer, "#image-manager-rebuild-thumbs", "click", async (i, r) => {
            r.disabled = !0, this.lastSelected && await this.rebuildThumbnails(this.lastSelected.id), r.disabled = !1
        }), this.formContainer.addEventListener("ajax-form-success", () => {
            this.refreshGallery(), this.resetEditForm()
        }), this.container.addEventListener("dropzone-upload-success", this.refreshGallery.bind(this));
        let t = this.listContainer.parentElement,
            e = [];
        t.addEventListener("wheel", i => {
            if (!(Math.ceil(t.scrollHeight - t.scrollTop) === t.clientHeight) || i.deltaY < 1) return;
            let s = Date.now() - 1e3;
            e.push(Date.now()), e = e.filter(a => a >= s), e.length > 5 && this.canLoadMore() && this.runLoadMore()
        })
    }
    show(t, e = "gallery") {
        this.resetAll(), this.callback = t, this.type = e, this.getPopup().show();
        let i = e !== "gallery";
        this.dropzoneContainer.classList.toggle("hidden", i), this.uploadButton.classList.toggle("hidden", i), this.uploadHint.classList.toggle("hidden", i), window.$components.firstOnElement(this.container, "dropzone").toggleActive(!i), this.hasData || (this.loadGallery(), this.hasData = !0)
    }
    hide() {
        this.getPopup().hide()
    }
    getPopup() {
        return window.$components.firstOnElement(this.popupEl, "popup")
    }
    async loadGallery() {
        let t = {
                page: this.page,
                search: this.searchInput.value || null,
                uploaded_to: this.uploadedTo,
                filter_type: this.filter === "all" ? null : this.filter
            },
            {
                data: e
            } = await window.$http.get(`images/${this.type}`, t);
        t.page === 1 && (this.listContainer.innerHTML = ""), this.addReturnedHtmlElementsToList(e), Le(this.listContainer)
    }
    addReturnedHtmlElementsToList(t) {
        let e = document.createElement("div");
        e.innerHTML = t;
        let i = e.querySelector(".load-more");
        i && (i.remove(), this.loadMore.innerHTML = i.innerHTML), this.loadMore.toggleAttribute("hidden", !i), window.$components.init(e);
        for (let r of [...e.children]) this.listContainer.appendChild(r)
    }
    setActiveFilterTab(t) {
        for (let e of this.filterTabs) {
            let i = e.dataset.filter === t;
            e.setAttribute("aria-selected", i ? "true" : "false")
        }
    }
    resetAll() {
        this.resetState(), this.resetListView(), this.resetSearchView(), this.resetEditForm(), this.setActiveFilterTab("all"), this.selectButton.classList.add("hidden")
    }
    resetSearchView() {
        this.searchInput.value = "", this.cancelSearch.toggleAttribute("hidden", !0)
    }
    resetEditForm() {
        this.formContainer.innerHTML = "", this.formContainerPlaceholder.removeAttribute("hidden")
    }
    resetListView() {
        De(this.listContainer), this.page = 1
    }
    refreshGallery() {
        this.resetListView(), this.loadGallery()
    }
    async onImageSelectEvent(t) {
        let e = JSON.parse(t.detail.data),
            i = e && e.id === this.lastSelected.id && Date.now() - this.lastSelectedTime < 400,
            r = t.target.classList.contains("selected");
        [...this.listContainer.querySelectorAll(".selected")].forEach(o => {
            o.classList.remove("selected")
        }), !r && !i ? (t.target.classList.add("selected"), e = await this.loadImageEditForm(e.id)) : i ? i && (e = this.lastSelected) : this.resetEditForm(), this.selectButton.classList.toggle("hidden", r), i && this.callback && (this.callback(e), this.hide()), this.lastSelected = e, this.lastSelectedTime = Date.now()
    }
    async loadImageEditForm(t, e = !1) {
        e || (this.formContainer.innerHTML = "");
        let i = e ? {
                delete: !0
            } : {},
            {
                data: r
            } = await window.$http.get(`/images/edit/${t}`, i);
        this.formContainer.innerHTML = r, this.formContainerPlaceholder.setAttribute("hidden", ""), window.$components.init(this.formContainer);
        let o = this.formContainer.querySelector("#image-manager-form-image-data");
        return JSON.parse(o.text)
    }
    runLoadMore() {
        De(this.loadMore), this.page += 1, this.loadGallery()
    }
    canLoadMore() {
        return this.loadMore.querySelector("button") && !this.loadMore.hasAttribute("hidden")
    }
    async rebuildThumbnails(t) {
        try {
            let e = await window.$http.put(`/images/${t}/rebuild-thumbnails`);
            window.$events.success(e.data), this.refreshGallery()
        } catch (e) {
            window.$events.showResponseError(e)
        }
    }
};
var ii = class extends g {
    setup() {
        this.imageElem = this.$refs.image, this.imageInput = this.$refs.imageInput, this.resetInput = this.$refs.resetInput, this.removeInput = this.$refs.removeInput, this.resetButton = this.$refs.resetButton, this.removeButton = this.$refs.removeButton || null, this.defaultImage = this.$opts.defaultImage, this.setupListeners()
    }
    setupListeners() {
        this.resetButton.addEventListener("click", this.reset.bind(this)), this.removeButton && this.removeButton.addEventListener("click", this.removeImage.bind(this)), this.imageInput.addEventListener("change", this.fileInputChange.bind(this))
    }
    fileInputChange() {
        this.resetInput.setAttribute("disabled", "disabled"), this.removeInput && this.removeInput.setAttribute("disabled", "disabled");
        for (let t of this.imageInput.files) this.imageElem.src = window.URL.createObjectURL(t);
        this.imageElem.classList.remove("none")
    }
    reset() {
        this.imageInput.value = "", this.imageElem.src = this.defaultImage, this.resetInput.removeAttribute("disabled"), this.removeInput && this.removeInput.setAttribute("disabled", "disabled"), this.imageElem.classList.remove("none")
    }
    removeImage() {
        this.imageInput.value = "", this.imageElem.classList.add("none"), this.removeInput.removeAttribute("disabled"), this.resetInput.setAttribute("disabled", "disabled")
    }
};
var ri = class extends g {
    setup() {
        this.elem = this.$el, this.menu = this.$refs.menu, this.sortInput = this.$refs.sort, this.orderInput = this.$refs.order, this.form = this.$refs.form, this.setupListeners()
    }
    setupListeners() {
        this.menu.addEventListener("click", t => {
            t.target.closest("[data-sort-value]") !== null && this.sortOptionClick(t)
        }), this.elem.addEventListener("click", t => {
            t.target.closest("[data-sort-dir]") !== null && this.sortDirectionClick(t)
        })
    }
    sortOptionClick(t) {
        let e = t.target.closest("[data-sort-value]");
        this.sortInput.value = e.getAttribute("data-sort-value"), t.preventDefault(), this.form.submit()
    }
    sortDirectionClick(t) {
        let e = this.orderInput.value;
        this.orderInput.value = e === "asc" ? "desc" : "asc", t.preventDefault(), this.form.submit()
    }
};
var Hc = Wo(Bc()),
    Uc = Wo(zc()),
    wi = class {
        constructor() {
            this.renderer = new Hc.default({
                html: !0
            }), this.renderer.use(Uc.default, {
                label: !0
            })
        }
        getRenderer() {
            return this.renderer
        }
        render(t) {
            return this.renderer.render(t)
        }
    };

function rf(n, t) {
    return document.createElement(n, t)
}

function of(n, t, e) {
    return document.createElementNS(n, t, e)
}

function sf() {
    return te(document.createDocumentFragment())
}

function af(n) {
    return document.createTextNode(n)
}

function lf(n) {
    return document.createComment(n)
}

function cf(n, t, e) {
    if (qt(n)) {
        let i = n;
        for (; i && qt(i);) i = te(i).parent;
        n = i ?? n
    }
    qt(t) && (t = te(t, n)), e && qt(e) && (e = te(e).firstChildNode), n.insertBefore(t, e)
}

function uf(n, t) {
    n.removeChild(t)
}

function hf(n, t) {
    qt(t) && (t = te(t, n)), n.appendChild(t)
}

function jc(n) {
    if (qt(n)) {
        for (; n && qt(n);) n = te(n).parent;
        return n ?? null
    }
    return n.parentNode
}

function df(n) {
    var t;
    if (qt(n)) {
        let e = te(n),
            i = jc(e);
        if (i && e.lastChildNode) {
            let r = Array.from(i.childNodes),
                o = r.indexOf(e.lastChildNode);
            return (t = r[o + 1]) !== null && t !== void 0 ? t : null
        }
        return null
    }
    return n.nextSibling
}

function pf(n) {
    return n.tagName
}

function ff(n, t) {
    n.textContent = t
}

function mf(n) {
    return n.textContent
}

function gf(n) {
    return n.nodeType === 1
}

function bf(n) {
    return n.nodeType === 3
}

function vf(n) {
    return n.nodeType === 8
}

function qt(n) {
    return n.nodeType === 11
}

function te(n, t) {
    var e, i, r;
    let o = n;
    return (e = o.parent) !== null && e !== void 0 || (o.parent = t ?? null), (i = o.firstChildNode) !== null && i !== void 0 || (o.firstChildNode = n.firstChild), (r = o.lastChildNode) !== null && r !== void 0 || (o.lastChildNode = n.lastChild), o
}
var yi = {
    createElement: rf,
    createElementNS: of,
    createTextNode: af,
    createDocumentFragment: sf,
    createComment: lf,
    insertBefore: cf,
    removeChild: uf,
    appendChild: hf,
    parentNode: jc,
    nextSibling: df,
    tagName: pf,
    setTextContent: ff,
    getTextContent: mf,
    isElement: gf,
    isText: bf,
    isComment: vf,
    isDocumentFragment: qt
};

function Bt(n, t, e, i, r) {
    let o = t === void 0 ? void 0 : t.key;
    return {
        sel: n,
        data: t,
        children: e,
        text: i,
        elm: r,
        key: o
    }
}
var Vc = Array.isArray;

function Wc(n) {
    return typeof n == "string" || typeof n == "number" || n instanceof String || n instanceof Number
}

function Co(n) {
    return n === void 0
}

function ut(n) {
    return n !== void 0
}
var Eo = Bt("", {}, [], void 0, void 0);

function Je(n, t) {
    var e, i;
    let r = n.key === t.key,
        o = ((e = n.data) === null || e === void 0 ? void 0 : e.is) === ((i = t.data) === null || i === void 0 ? void 0 : i.is),
        s = n.sel === t.sel,
        a = !n.sel && n.sel === t.sel ? typeof n.text == typeof t.text : !0;
    return s && r && o && a
}

function yf() {
    throw new Error("The document fragment is not supported on this platform.")
}

function xf(n, t) {
    return n.isElement(t)
}

function kf(n, t) {
    return n.isDocumentFragment(t)
}

function Cf(n, t, e) {
    var i;
    let r = {};
    for (let o = t; o <= e; ++o) {
        let s = (i = n[o]) === null || i === void 0 ? void 0 : i.key;
        s !== void 0 && (r[s] = o)
    }
    return r
}
var Ef = ["create", "update", "remove", "destroy", "pre", "post"];

function _o(n, t, e) {
    let i = {
            create: [],
            update: [],
            remove: [],
            destroy: [],
            pre: [],
            post: []
        },
        r = t !== void 0 ? t : yi;
    for (let p of Ef)
        for (let m of n) {
            let w = m[p];
            w !== void 0 && i[p].push(w)
        }

    function o(p) {
        let m = p.id ? "#" + p.id : "",
            w = p.getAttribute("class"),
            v = w ? "." + w.split(" ").join(".") : "";
        return Bt(r.tagName(p).toLowerCase() + m + v, {}, [], void 0, p)
    }

    function s(p) {
        return Bt(void 0, {}, [], void 0, p)
    }

    function a(p, m) {
        return function() {
            if (--m === 0) {
                let v = r.parentNode(p);
                r.removeChild(v, p)
            }
        }
    }

    function l(p, m) {
        var w, v, b, k;
        let x, E = p.data;
        if (E !== void 0) {
            let D = (w = E.hook) === null || w === void 0 ? void 0 : w.init;
            ut(D) && (D(p), E = p.data)
        }
        let y = p.children,
            S = p.sel;
        if (S === "!") Co(p.text) && (p.text = ""), p.elm = r.createComment(p.text);
        else if (S !== void 0) {
            let D = S.indexOf("#"),
                M = S.indexOf(".", D),
                T = D > 0 ? D : S.length,
                P = M > 0 ? M : S.length,
                H = D !== -1 || M !== -1 ? S.slice(0, Math.min(T, P)) : S,
                U = p.elm = ut(E) && ut(x = E.ns) ? r.createElementNS(x, H, E) : r.createElement(H, E);
            for (T < P && U.setAttribute("id", S.slice(T + 1, P)), M > 0 && U.setAttribute("class", S.slice(P + 1).replace(/\./g, " ")), x = 0; x < i.create.length; ++x) i.create[x](Eo, p);
            if (Vc(y))
                for (x = 0; x < y.length; ++x) {
                    let W = y[x];
                    W != null && r.appendChild(U, l(W, m))
                } else Wc(p.text) && r.appendChild(U, r.createTextNode(p.text));
            let et = p.data.hook;
            ut(et) && ((v = et.create) === null || v === void 0 || v.call(et, Eo, p), et.insert && m.push(p))
        } else if (!((b = e?.experimental) === null || b === void 0) && b.fragments && p.children) {
            for (p.elm = ((k = r.createDocumentFragment) !== null && k !== void 0 ? k : yf)(), x = 0; x < i.create.length; ++x) i.create[x](Eo, p);
            for (x = 0; x < p.children.length; ++x) {
                let D = p.children[x];
                D != null && r.appendChild(p.elm, l(D, m))
            }
        } else p.elm = r.createTextNode(p.text);
        return p.elm
    }

    function c(p, m, w, v, b, k) {
        for (; v <= b; ++v) {
            let x = w[v];
            x != null && r.insertBefore(p, l(x, k), m)
        }
    }

    function u(p) {
        var m, w;
        let v = p.data;
        if (v !== void 0) {
            (w = (m = v?.hook) === null || m === void 0 ? void 0 : m.destroy) === null || w === void 0 || w.call(m, p);
            for (let b = 0; b < i.destroy.length; ++b) i.destroy[b](p);
            if (p.children !== void 0)
                for (let b = 0; b < p.children.length; ++b) {
                    let k = p.children[b];
                    k != null && typeof k != "string" && u(k)
                }
        }
    }

    function h(p, m, w, v) {
        for (var b, k; w <= v; ++w) {
            let x, E, y = m[w];
            if (y != null)
                if (ut(y.sel)) {
                    u(y), x = i.remove.length + 1, E = a(y.elm, x);
                    for (let D = 0; D < i.remove.length; ++D) i.remove[D](y, E);
                    let S = (k = (b = y?.data) === null || b === void 0 ? void 0 : b.hook) === null || k === void 0 ? void 0 : k.remove;
                    ut(S) ? S(y, E) : E()
                } else y.children ? (u(y), h(p, y.children, 0, y.children.length - 1)) : r.removeChild(p, y.elm)
        }
    }

    function d(p, m, w, v) {
        let b = 0,
            k = 0,
            x = m.length - 1,
            E = m[0],
            y = m[x],
            S = w.length - 1,
            D = w[0],
            M = w[S],
            T, P, H, U;
        for (; b <= x && k <= S;) E == null ? E = m[++b] : y == null ? y = m[--x] : D == null ? D = w[++k] : M == null ? M = w[--S] : Je(E, D) ? (f(E, D, v), E = m[++b], D = w[++k]) : Je(y, M) ? (f(y, M, v), y = m[--x], M = w[--S]) : Je(E, M) ? (f(E, M, v), r.insertBefore(p, E.elm, r.nextSibling(y.elm)), E = m[++b], M = w[--S]) : Je(y, D) ? (f(y, D, v), r.insertBefore(p, y.elm, E.elm), y = m[--x], D = w[++k]) : (T === void 0 && (T = Cf(m, b, x)), P = T[D.key], Co(P) ? r.insertBefore(p, l(D, v), E.elm) : (H = m[P], H.sel !== D.sel ? r.insertBefore(p, l(D, v), E.elm) : (f(H, D, v), m[P] = void 0, r.insertBefore(p, H.elm, E.elm))), D = w[++k]);
        k <= S && (U = w[S + 1] == null ? null : w[S + 1].elm, c(p, U, w, k, S, v)), b <= x && h(p, m, b, x)
    }

    function f(p, m, w) {
        var v, b, k, x, E, y, S, D;
        let M = (v = m.data) === null || v === void 0 ? void 0 : v.hook;
        (b = M?.prepatch) === null || b === void 0 || b.call(M, p, m);
        let T = m.elm = p.elm;
        if (p === m) return;
        if (m.data !== void 0 || ut(m.text) && m.text !== p.text) {
            (k = m.data) !== null && k !== void 0 || (m.data = {}), (x = p.data) !== null && x !== void 0 || (p.data = {});
            for (let U = 0; U < i.update.length; ++U) i.update[U](p, m);
            (S = (y = (E = m.data) === null || E === void 0 ? void 0 : E.hook) === null || y === void 0 ? void 0 : y.update) === null || S === void 0 || S.call(y, p, m)
        }
        let P = p.children,
            H = m.children;
        Co(m.text) ? ut(P) && ut(H) ? P !== H && d(T, P, H, w) : ut(H) ? (ut(p.text) && r.setTextContent(T, ""), c(T, null, H, 0, H.length - 1, w)) : ut(P) ? h(T, P, 0, P.length - 1) : ut(p.text) && r.setTextContent(T, "") : p.text !== m.text && (ut(P) && h(T, P, 0, P.length - 1), r.setTextContent(T, m.text)), (D = M?.postpatch) === null || D === void 0 || D.call(M, p, m)
    }
    return function(m, w) {
        let v, b, k, x = [];
        for (v = 0; v < i.pre.length; ++v) i.pre[v]();
        for (xf(r, m) ? m = o(m) : kf(r, m) && (m = s(m)), Je(m, w) ? f(m, w, x) : (b = m.elm, k = r.parentNode(b), l(w, x), k !== null && (r.insertBefore(k, w.elm, r.nextSibling(b)), h(k, [m], 0, 0))), v = 0; v < x.length; ++v) x[v].data.hook.insert(x[v]);
        for (v = 0; v < i.post.length; ++v) i.post[v]();
        return w
    }
}

function So(n, t, e) {
    if (n.ns = "http://www.w3.org/2000/svg", e !== "foreignObject" && t !== void 0)
        for (let i = 0; i < t.length; ++i) {
            let r = t[i];
            if (typeof r == "string") continue;
            let o = r.data;
            o !== void 0 && So(o, r.children, r.sel)
        }
}

function Qe(n, t) {
    let e = t !== void 0 ? t : yi,
        i;
    if (e.isElement(n)) {
        let r = n.id ? "#" + n.id : "",
            o = n.getAttribute("class"),
            s = o ? "." + o.split(" ").join(".") : "",
            a = e.tagName(n).toLowerCase() + r + s,
            l = {},
            c = {},
            u = {},
            h = [],
            d, f, p, m = n.attributes,
            w = n.childNodes;
        for (f = 0, p = m.length; f < p; f++) d = m[f].nodeName, d[0] === "d" && d[1] === "a" && d[2] === "t" && d[3] === "a" && d[4] === "-" ? c[d.slice(5)] = m[f].nodeValue || "" : d !== "id" && d !== "class" && (l[d] = m[f].nodeValue);
        for (f = 0, p = w.length; f < p; f++) h.push(Qe(w[f], t));
        return Object.keys(l).length > 0 && (u.attrs = l), Object.keys(c).length > 0 && (u.dataset = c), a[0] === "s" && a[1] === "v" && a[2] === "g" && (a.length === 3 || a[3] === "." || a[3] === "#") && So(u, h, a), Bt(a, u, h, void 0, n)
    } else return e.isText(n) ? (i = e.getTextContent(n), Bt(void 0, void 0, void 0, i, n)) : e.isComment(n) ? (i = e.getTextContent(n), Bt("!", {}, [], i, n)) : Bt("", {}, [], void 0, n)
}
var _f = "http://www.w3.org/1999/xlink",
    Sf = "http://www.w3.org/XML/1998/namespace";

function Gc(n, t) {
    let e, i = t.elm,
        r = n.data.attrs,
        o = t.data.attrs;
    if (!(!r && !o) && r !== o) {
        r = r || {}, o = o || {};
        for (e in o) {
            let s = o[e];
            r[e] !== s && (s === !0 ? i.setAttribute(e, "") : s === !1 ? i.removeAttribute(e) : e.charCodeAt(0) !== 120 ? i.setAttribute(e, s) : e.charCodeAt(3) === 58 ? i.setAttributeNS(Sf, e, s) : e.charCodeAt(5) === 58 ? i.setAttributeNS(_f, e, s) : i.setAttribute(e, s))
        }
        for (e in r) e in o || i.removeAttribute(e)
    }
}
var Ao = {
    create: Gc,
    update: Gc
};
var xi;

function Af() {
    return xi || (xi = _o([Ao]), xi)
}

function Kc(n, t) {
    let e = document.createElement("div");
    e.innerHTML = t, Af()(Qe(n), Qe(e))
}
var ki = class {
    constructor(t) {
        this.editor = t, this.container = t.config.displayEl, this.doc = null, this.lastDisplayClick = 0, this.container.contentDocument.readyState === "complete" ? this.onLoad() : this.container.addEventListener("load", this.onLoad.bind(this)), this.updateVisibility(t.settings.get("showPreview")), t.settings.onChange("showPreview", e => this.updateVisibility(e))
    }
    updateVisibility(t) {
        let e = this.container.closest(".markdown-editor-wrap");
        e.style.display = t ? null : "none"
    }
    onLoad() {
        this.doc = this.container.contentDocument, this.loadStylesIntoDisplay(), this.doc.body.className = "page-content", this.doc.addEventListener("click", this.onDisplayClick.bind(this))
    }
    onDisplayClick(t) {
        let e = Date.now() - this.lastDisplayClick < 300,
            i = t.target.closest("a");
        if (i !== null) {
            t.preventDefault(), window.open(i.getAttribute("href"));
            return
        }
        let r = t.target.closest("[drawio-diagram]");
        if (r !== null && e) {
            this.editor.actions.editDrawing(r);
            return
        }
        this.lastDisplayClick = Date.now()
    }
    loadStylesIntoDisplay() {
        this.doc.documentElement.classList.add("markdown-editor-display"), document.documentElement.classList.contains("dark-mode") && (this.doc.documentElement.style.backgroundColor = "#222", this.doc.documentElement.classList.add("dark-mode")), this.doc.head.innerHTML = "";
        let t = document.head.querySelectorAll("style,link[rel=stylesheet]");
        for (let e of t) {
            let i = e.cloneNode(!0);
            this.doc.head.appendChild(i)
        }
    }
    patchWithHtml(t) {
        let {
            body: e
        } = this.doc;
        if (e.children.length === 0) {
            let r = document.createElement("div");
            this.doc.body.append(r)
        }
        let i = e.children[0];
        Kc(i, t)
    }
    scrollToIndex(t) {
        let e = this.doc.body?.children[0]?.children;
        if (e && e.length <= t) return;
        (t === -1 ? e[e.length - 1] : e[t]).scrollIntoView({
            block: "start",
            inline: "nearest",
            behavior: "smooth"
        })
    }
};

function Ci(n) {
    return new Promise((t, e) => {
        n.oncomplete = n.onsuccess = () => t(n.result), n.onabort = n.onerror = () => e(n.error)
    })
}

function Df(n, t) {
    let e = indexedDB.open(n);
    e.onupgradeneeded = () => e.result.createObjectStore(t);
    let i = Ci(e);
    return (r, o) => i.then(s => o(s.transaction(t, r).objectStore(t)))
}
var Do;

function Lo() {
    return Do || (Do = Df("keyval-store", "keyval")), Do
}

function To(n, t = Lo()) {
    return t("readonly", e => Ci(e.get(n)))
}

function $o(n, t, e = Lo()) {
    return e("readwrite", i => (i.put(t, n), Ci(i.transaction)))
}

function Io(n, t = Lo()) {
    return t("readwrite", e => (e.delete(n), Ci(e.transaction)))
}
var $t = null,
    qo, Ei, Mo, Fo = "last-drawing-save";

function Bo(n) {
    $t.contentWindow.postMessage(JSON.stringify(n), qo)
}

function Tf(n) {
    $o(Fo, n.data), Mo && Mo(n.data).then(() => {
        Io(Fo)
    })
}

function $f(n) {
    Bo({
        action: "export",
        format: "xmlpng",
        xml: n.xml,
        spin: "Updating drawing"
    })
}

function If() {
    Ei && Ei().then(n => {
        Bo({
            action: "load",
            autosave: 1,
            xml: n
        })
    })
}

function Mf() {
    let n = {};
    window.$events.emitPublic($t, "editor-drawio::configure", {
        config: n
    }), Bo({
        action: "configure",
        config: n
    })
}

function Zc() {
    window.removeEventListener("message", Xc), $t && document.body.removeChild($t)
}

function Xc(n) {
    if (!n.data || n.data.length < 1 || n.origin !== qo) return;
    let t = JSON.parse(n.data);
    t.event === "init" ? If() : t.event === "exit" ? Zc() : t.event === "save" ? $f(t) : t.event === "export" ? Tf(t) : t.event === "configure" && Mf()
}
async function Ff() {
    let n = await To(Fo),
        t = document.getElementById("unsaved-drawing-dialog");
    t || console.error("Missing expected unsaved-drawing dialog"), n && await window.$components.firstOnElement(t, "confirm-dialog").show() && (Ei = async () => n)
}
async function tn(n, t, e) {
    Ei = t, Mo = e, await Ff(), $t = document.createElement("iframe"), $t.setAttribute("frameborder", "0"), window.addEventListener("message", Xc), $t.setAttribute("src", n), $t.setAttribute("class", "fullscreen"), $t.style.backgroundColor = "#FFFFFF", document.body.appendChild($t), qo = new URL(n).origin
}
async function Po(n, t) {
    let e = {
        image: n,
        uploaded_to: t
    };
    return (await window.$http.post(window.baseUrl("/images/drawio"), e)).data
}

function ee() {
    Zc()
}
async function _i(n) {
    try {
        return `data:image/png;base64,${(await window.$http.get(window.baseUrl(`/images/drawio/base64/${n}`))).data.content}`
    } catch (t) {
        throw t instanceof window.$http.HttpError && window.$events.showResponseError(t), ee(), t
    }
}
var en, Oo, xe, Si, ke, Ai, Pt, ne, Wt, ye, rt, ht, nn, Ro, rn, No, Ce, Di, dt, vt, Ti, Jc, Li = class {
    constructor(t) {
        ot(this, en);
        ot(this, xe);
        ot(this, ke);
        ot(this, Pt);
        ot(this, Wt);
        ot(this, rt);
        ot(this, nn);
        ot(this, rn);
        ot(this, Ce);
        ot(this, dt);
        ot(this, Ti);
        this.editor = t, this.lastContent = {
            html: "",
            markdown: ""
        }
    }
    updateAndRender() {
        let t = L(this, xe, Si).call(this);
        this.editor.config.inputEl.value = t;
        let e = this.editor.markdown.render(t);
        window.$events.emit("editor-html-change", ""), window.$events.emit("editor-markdown-change", ""), this.lastContent.html = e, this.lastContent.markdown = t, this.editor.display.patchWithHtml(e)
    }
    getContent() {
        return this.lastContent
    }
    showImageInsert() {
        window.$components.first("image-manager").show(e => {
            let i = e.thumbs?.display || e.url,
                o = `[![${L(this,Wt,ye).call(this)||e.name}](${i})](${e.url})`;
            L(this, Pt, ne).call(this, o, o.length)
        }, "gallery")
    }
    insertImage() {
        let t = `![${L(this,Wt,ye).call(this)}](http://)`;
        L(this, Pt, ne).call(this, t, t.length - 1)
    }
    insertLink() {
        let t = L(this, Wt, ye).call(this),
            e = `[${t}]()`,
            i = t === "" ? -3 : -1;
        L(this, Pt, ne).call(this, e, e.length + i)
    }
    showImageManager() {
        let t = L(this, rt, ht).call(this);
        window.$components.first("image-manager").show(i => {
            L(this, en, Oo).call(this, i, t)
        }, "drawio")
    }
    showLinkSelector() {
        let t = L(this, rt, ht).call(this),
            e = window.$components.first("entity-selector-popup"),
            i = L(this, Wt, ye).call(this, t);
        e.show(r => {
            let s = `[${i||r.name}](${r.link})`;
            L(this, Pt, ne).call(this, s, s.length, t)
        }, i)
    }
    startDrawing() {
        let t = this.editor.config.drawioUrl;
        if (!t) return;
        let e = L(this, rt, ht).call(this);
        tn(t, () => Promise.resolve(""), async i => {
            let r = {
                image: i,
                uploaded_to: Number(this.editor.config.pageId)
            };
            try {
                let o = await window.$http.post("/images/drawio", r);
                L(this, en, Oo).call(this, o.data, e), ee()
            } catch (o) {
                throw this.handleDrawingUploadError(o), new Error(`Failed to save image with error: ${o}`)
            }
        })
    }
    editDrawing(t) {
        let {
            drawioUrl: e
        } = this.editor.config;
        if (!e) return;
        let i = L(this, rt, ht).call(this),
            r = t.getAttribute("drawio-diagram");
        tn(e, () => _i(r), async o => {
            let s = {
                image: o,
                uploaded_to: Number(this.editor.config.pageId)
            };
            try {
                let a = await window.$http.post("/images/drawio", s),
                    l = `<div drawio-diagram="${a.data.id}"><img src="${a.data.url}"></div>`,
                    c = L(this, xe, Si).call(this).split(`
`).map(u => u.indexOf(`drawio-diagram="${r}"`) !== -1 ? l : u).join(`
`);
                L(this, ke, Ai).call(this, c, i), ee()
            } catch (a) {
                throw this.handleDrawingUploadError(a), new Error(`Failed to save image with error: ${a}`)
            }
        })
    }
    handleDrawingUploadError(t) {
        t.status === 413 ? window.$events.emit("error", this.editor.config.text.serverUploadLimit) : window.$events.emit("error", this.editor.config.text.imageUploadError), console.error(t)
    }
    fullScreen() {
        let {
            container: t
        } = this.editor.config, e = t.classList.contains("fullscreen");
        t.classList.toggle("fullscreen", !e), document.body.classList.toggle("markdown-fullscreen", !e)
    }
    scrollToText(t) {
        if (!t) return;
        let e = this.editor.cm.state.doc,
            i = 1,
            r = -1;
        for (let s of e.iterLines()) {
            if (s.includes(t)) {
                r = i;
                break
            }
            i += 1
        }
        if (r === -1) return;
        let o = e.line(r);
        L(this, Ti, Jc).call(this, o.from, o.to, !0), this.focus()
    }
    focus() {
        this.editor.cm.hasFocus || this.editor.cm.focus()
    }
    insertContent(t) {
        L(this, Pt, ne).call(this, t, t.length)
    }
    prependContent(t) {
        t = L(this, nn, Ro).call(this, t);
        let i = L(this, rt, ht).call(this).from + t.length + 1;
        L(this, dt, vt).call(this, 0, 0, `${t}
`, i), this.focus()
    }
    appendContent(t) {
        t = L(this, nn, Ro).call(this, t), L(this, dt, vt).call(this, this.editor.cm.state.doc.length, `
${t}`), this.focus()
    }
    replaceContent(t) {
        L(this, ke, Ai).call(this, t)
    }
    replaceLineStart(t) {
        let e = L(this, rt, ht).call(this),
            i = this.editor.cm.state.doc.lineAt(e.from),
            r = i.text,
            o = r.split(" ")[0];
        if (o === t) {
            let c = r.replace(`${t} `, ""),
                u = e.from + (c.length - r.length);
            L(this, dt, vt).call(this, i.from, i.to, c, u);
            return
        }
        let s = r;
        /^[#>`]/.test(o) ? s = r.replace(o, t).trim() : t !== "" && (s = `${t} ${r}`);
        let l = e.from + (s.length - r.length);
        L(this, dt, vt).call(this, i.from, i.to, s, l)
    }
    wrapSelection(t, e) {
        let i = L(this, rt, ht).call(this),
            r = L(this, Wt, ye).call(this, i);
        if (!r) {
            L(this, Ce, Di).call(this, t, e);
            return
        }
        let o = r,
            s;
        r.startsWith(t) && r.endsWith(e) ? (o = r.slice(t.length, r.length - e.length), s = i.extend(i.from, i.to - (t.length + e.length))) : (o = `${t}${r}${e}`, s = i.extend(i.from, i.to + (t.length + e.length))), L(this, dt, vt).call(this, i.from, i.to, o, s.anchor, s.head)
    }
    replaceLineStartForOrderedList() {
        let t = L(this, rt, ht).call(this),
            e = this.editor.cm.state.doc.lineAt(t.from),
            r = this.editor.cm.state.doc.line(e.number - 1).text.match(/^(\s*)(\d)([).])\s/) || [],
            o = (Number(r[2]) || 0) + 1,
            s = r[1] || "",
            a = r[3] || ".",
            l = `${s}${o}${a}`;
        return this.replaceLineStart(l)
    }
    cycleCalloutTypeAtSelection() {
        let t = L(this, rt, ht).call(this),
            e = this.editor.cm.state.doc.lineAt(t.from),
            i = ["info", "success", "warning", "danger"],
            r = i.join("|"),
            s = new RegExp(`class="((${r})\\s+callout|callout\\s+(${r}))"`, "i").exec(e.text),
            a = (s ? s[2] || s[3] : "").toLowerCase();
        if (a === i[i.length - 1]) L(this, Ce, Di).call(this, `<p class="callout ${i[i.length-1]}">`, "</p>");
        else if (a === "") L(this, Ce, Di).call(this, '<p class="callout info">', "</p>");
        else {
            let l = i.indexOf(a) + 1,
                c = i[l],
                u = e.text.replace(s[0], s[0].replace(a, c)),
                h = u.length - e.text.length;
            L(this, dt, vt).call(this, e.from, e.to, u, t.anchor + h, t.head + h)
        }
    }
    syncDisplayPosition(t) {
        let e = t.target;
        if (Math.abs(e.scrollHeight - e.clientHeight - e.scrollTop) < 1) {
            this.editor.display.scrollToIndex(-1);
            return
        }
        let r = this.editor.cm.lineBlockAtHeight(e.scrollTop),
            o = this.editor.cm.state.sliceDoc(0, r.from),
            l = new DOMParser().parseFromString(this.editor.markdown.render(o), "text/html").documentElement.querySelectorAll("body > *");
        this.editor.display.scrollToIndex(l.length)
    }
    async insertTemplate(t, e, i) {
        let r = this.editor.cm.posAtCoords({
                x: e,
                y: i
            }, !1),
            {
                data: o
            } = await window.$http.get(`/templates/${t}`),
            s = o.markdown || o.html;
        L(this, dt, vt).call(this, r, r, s, r)
    }
    insertClipboardImages(t, e, i) {
        let r = this.editor.cm.posAtCoords({
            x: e,
            y: i
        }, !1);
        for (let o of t) this.uploadImage(o, r)
    }
    async uploadImage(t, e = null) {
        if (t === null || t.type.indexOf("image") !== 0) return;
        let i = "png";
        if (e === null && (e = L(this, rt, ht).call(this).from), t.name) {
            let c = t.name.match(/\.(.+)$/);
            c.length > 1 && (i = c[1])
        }
        let r = `image-${Math.random().toString(16).slice(2)}`,
            s = `![](${window.baseUrl(`/loading.gif#upload${r}`)})`;
        L(this, dt, vt).call(this, e, e, s, e);
        let a = `image-${Date.now()}.${i}`,
            l = new FormData;
        l.append("file", t, a), l.append("uploaded_to", this.editor.config.pageId);
        try {
            let {
                data: c
            } = await window.$http.post("/images/gallery", l), u = `[![](${c.thumbs.display})](${c.url})`;
            L(this, rn, No).call(this, s, u)
        } catch (c) {
            window.$events.error(c?.data?.message || this.editor.config.text.imageUploadError), L(this, rn, No).call(this, s, ""), console.error(c)
        }
    }
};
en = new WeakSet, Oo = function(t, e) {
    let i = `<div drawio-diagram="${t.id}"><img src="${t.url}"></div>`;
    L(this, Pt, ne).call(this, i, i.length, e)
}, xe = new WeakSet, Si = function() {
    return this.editor.cm.state.doc.toString()
}, ke = new WeakSet, Ai = function(t, e = null) {
    e = e || L(this, rt, ht).call(this);
    let i = this.editor.cm.state.toText(t),
        r = Math.min(e.from, i.length);
    L(this, dt, vt).call(this, 0, this.editor.cm.state.doc.length, t, r), this.focus()
}, Pt = new WeakSet, ne = function(t, e = 0, i = null) {
    i = i || this.editor.cm.state.selection.main;
    let r = i.from + e;
    L(this, dt, vt).call(this, i.from, i.to, t, r), this.focus()
}, Wt = new WeakSet, ye = function(t = null) {
    return t = t || L(this, rt, ht).call(this), this.editor.cm.state.sliceDoc(t.from, t.to)
}, rt = new WeakSet, ht = function() {
    return this.editor.cm.state.selection.main
}, nn = new WeakSet, Ro = function(t) {
    return t.replace(/\r\n|\r/g, `
`)
}, rn = new WeakSet, No = function(t, e) {
    let i = L(this, xe, Si).call(this).replace(t, e);
    L(this, ke, Ai).call(this, i)
}, Ce = new WeakSet, Di = function(t, e) {
    let i = L(this, rt, ht).call(this),
        r = this.editor.cm.state.doc.lineAt(i.from),
        o = r.text,
        s, a = 0;
    o.startsWith(t) && o.endsWith(e) ? (s = o.slice(t.length, o.length - e.length), a = -t.length) : (s = `${t}${o}${e}`, a = t.length), L(this, dt, vt).call(this, r.from, r.to, s, i.from + a)
}, dt = new WeakSet, vt = function(t, e = null, i = null, r = null, o = null) {
    let s = {
        changes: {
            from: t,
            to: e,
            insert: i
        }
    };
    r && (s.selection = {
        anchor: r
    }, o && (s.selection.head = o)), this.editor.cm.dispatch(s)
}, Ti = new WeakSet, Jc = function(t, e, i = !1) {
    this.editor.cm.dispatch({
        selection: {
            anchor: t,
            head: e
        },
        scrollIntoView: i
    })
};
var $i = class {
    constructor(t) {
        this.settingMap = {
            scrollSync: !0,
            showPreview: !0,
            editorWidth: 50
        }, this.changeListeners = {}, this.loadFromLocalStorage(), this.applyToInputs(t), this.listenToInputChanges(t)
    }
    applyToInputs(t) {
        for (let e of t) {
            let i = e.getAttribute("name").replace("md-", "");
            e.checked = this.settingMap[i]
        }
    }
    listenToInputChanges(t) {
        for (let e of t) e.addEventListener("change", () => {
            let i = e.getAttribute("name").replace("md-", "");
            this.set(i, e.checked)
        })
    }
    loadFromLocalStorage() {
        let t = window.localStorage.getItem("md-editor-settings");
        if (!t) return;
        let e = JSON.parse(t);
        for (let [i, r] of Object.entries(e)) r !== null && this.settingMap[i] !== void 0 && (this.settingMap[i] = r)
    }
    set(t, e) {
        this.settingMap[t] = e, window.localStorage.setItem("md-editor-settings", JSON.stringify(this.settingMap));
        for (let i of this.changeListeners[t] || []) i(e)
    }
    get(t) {
        return this.settingMap[t] || null
    }
    onChange(t, e) {
        let i = this.changeListeners[t] || [];
        i.push(e), this.changeListeners[t] = i
    }
};

function Ii({
    html: n,
    markdown: t
}) {
    return t || n
}

function Qc(n) {
    window.$events.listen("editor::replace", t => {
        let e = Ii(t);
        n.actions.replaceContent(e)
    }), window.$events.listen("editor::append", t => {
        let e = Ii(t);
        n.actions.appendContent(e)
    }), window.$events.listen("editor::prepend", t => {
        let e = Ii(t);
        n.actions.prependContent(e)
    }), window.$events.listen("editor::insert", t => {
        let e = Ii(t);
        n.actions.insertContent(e)
    }), window.$events.listen("editor::focus", () => {
        n.actions.focus()
    })
}

function qf(n) {
    let t = {};
    return t["Shift-Mod-i"] = () => n.actions.insertImage(), t["Mod-s"] = () => window.$events.emit("editor-save-draft"), t["Mod-Enter"] = () => window.$events.emit("editor-save-page"), t["Shift-Mod-k"] = () => n.actions.showLinkSelector(), t["Mod-k"] = () => n.actions.insertLink(), t["Mod-1"] = () => n.actions.replaceLineStart("##"), t["Mod-2"] = () => n.actions.replaceLineStart("###"), t["Mod-3"] = () => n.actions.replaceLineStart("####"), t["Mod-4"] = () => n.actions.replaceLineStart("#####"), t["Mod-5"] = () => n.actions.replaceLineStart(""), t["Mod-d"] = () => n.actions.replaceLineStart(""), t["Mod-6"] = () => n.actions.replaceLineStart(">"), t["Mod-q"] = () => n.actions.replaceLineStart(">"), t["Mod-7"] = () => n.actions.wrapSelection("\n```\n", "\n```"), t["Mod-8"] = () => n.actions.wrapSelection("`", "`"), t["Shift-Mod-e"] = () => n.actions.wrapSelection("`", "`"), t["Mod-9"] = () => n.actions.cycleCalloutTypeAtSelection(), t["Mod-p"] = () => n.actions.replaceLineStart("-"), t["Mod-o"] = () => n.actions.replaceLineStartForOrderedList(), t
}

function tu(n) {
    let t = qf(n),
        e = [],
        i = r => () => (r(), !0);
    for (let [r, o] of Object.entries(t)) e.push({
        key: r,
        run: i(o),
        preventDefault: !0
    });
    return e
}
async function eu(n) {
    let t = await window.importVersioned("code");

    function e(a) {
        a.docChanged && n.actions.updateAndRender()
    }
    let i = Nt(n.actions.syncDisplayPosition.bind(n.actions), 100, !1),
        r = n.settings.get("scrollSync");
    n.settings.onChange("scrollSync", a => {
        r = a
    });
    let o = {
            scroll: a => r && i(a),
            drop: a => {
                let l = a.dataTransfer.getData("bookstack/template");
                l && (a.preventDefault(), n.actions.insertTemplate(l, a.pageX, a.pageY));
                let u = new Ft(a.dataTransfer).getImages();
                u.length > 0 && (a.stopPropagation(), a.preventDefault(), n.actions.insertClipboardImages(u, a.pageX, a.pageY))
            },
            paste: a => {
                let l = new Ft(a.clipboardData || a.dataTransfer);
                if (!l.hasItems() || l.containsTabularData()) return;
                let c = l.getImages();
                for (let u of c) n.actions.uploadImage(u)
            }
        },
        s = t.markdownEditor(n.config.inputEl, e, o, tu(n));
    return window.mdEditorView = s, s
}
async function nu(n) {
    let t = {
        config: n,
        markdown: new wi,
        settings: new $i(n.settingInputs)
    };
    return t.actions = new Li(t), t.display = new ki(t), t.cm = await eu(t), Qc(t), t
}
var Mi = class extends g {
    setup() {
        this.elem = this.$el, this.pageId = this.$opts.pageId, this.textDirection = this.$opts.textDirection, this.imageUploadErrorText = this.$opts.imageUploadErrorText, this.serverUploadLimitText = this.$opts.serverUploadLimitText, this.display = this.$refs.display, this.input = this.$refs.input, this.divider = this.$refs.divider, this.displayWrap = this.$refs.displayWrap;
        let {
            settingContainer: t
        } = this.$refs, e = t.querySelectorAll('input[type="checkbox"]');
        this.editor = null, nu({
            pageId: this.pageId,
            container: this.elem,
            displayEl: this.display,
            inputEl: this.input,
            drawioUrl: this.getDrawioUrl(),
            settingInputs: Array.from(e),
            text: {
                serverUploadLimit: this.serverUploadLimitText,
                imageUploadError: this.imageUploadErrorText
            }
        }).then(i => {
            this.editor = i, this.setupListeners(), this.emitEditorEvents(), this.scrollToTextIfNeeded(), this.editor.actions.updateAndRender()
        })
    }
    emitEditorEvents() {
        window.$events.emitPublic(this.elem, "editor-markdown::setup", {
            markdownIt: this.editor.markdown.getRenderer(),
            displayEl: this.display,
            cmEditorView: this.editor.cm
        })
    }
    setupListeners() {
        this.elem.addEventListener("click", t => {
            let e = t.target.closest("button[data-action]");
            if (e === null) return;
            let i = e.getAttribute("data-action");
            if (i === "insertImage" && this.editor.actions.showImageInsert(), i === "insertLink" && this.editor.actions.showLinkSelector(), i === "insertDrawing" && (t.ctrlKey || t.metaKey)) {
                this.editor.actions.showImageManager();
                return
            }
            i === "insertDrawing" && this.editor.actions.startDrawing(), i === "fullscreen" && this.editor.actions.fullScreen()
        }), this.elem.addEventListener("click", t => {
            let e = t.target.closest(".editor-toolbar-label");
            if (!e) return;
            let i = this.elem.querySelectorAll(".markdown-editor-wrap");
            for (let r of i) r.classList.remove("active");
            e.closest(".markdown-editor-wrap").classList.add("active")
        }), this.handleDividerDrag()
    }
    handleDividerDrag() {
        this.divider.addEventListener("pointerdown", () => {
            let e = this.elem.getBoundingClientRect(),
                i = o => {
                    let s = o.pageX - e.left,
                        a = Math.min(Math.max(20, Math.floor(s / e.width * 100)), 80);
                    this.displayWrap.style.flexBasis = `${100-a}%`, this.editor.settings.set("editorWidth", a)
                },
                r = () => {
                    window.removeEventListener("pointermove", i), window.removeEventListener("pointerup", r), this.display.style.pointerEvents = null, document.body.style.userSelect = null
                };
            this.display.style.pointerEvents = "none", document.body.style.userSelect = "none", window.addEventListener("pointermove", i), window.addEventListener("pointerup", r)
        });
        let t = this.editor.settings.get("editorWidth");
        t && (this.displayWrap.style.flexBasis = `${100-t}%`)
    }
    scrollToTextIfNeeded() {
        let e = new URL(window.location).searchParams.get("content-text");
        e && this.editor.actions.scrollToText(e)
    }
    getDrawioUrl() {
        let t = document.querySelector("[drawio-url]");
        return t && t.getAttribute("drawio-url") || ""
    }
    getContent() {
        return this.editor.actions.getContent()
    }
};
var Fi = class extends g {
    setup() {
        this.container = this.$el, this.inputContainer = this.$refs.inputContainer, this.inviteOption = this.container.querySelector("input[name=send_invite]"), this.inviteOption && (this.inviteOption.addEventListener("change", this.inviteOptionChange.bind(this)), this.inviteOptionChange())
    }
    inviteOptionChange() {
        let t = this.inviteOption.value === "true",
            e = this.container.querySelectorAll("input[type=password]");
        for (let i of e) i.disabled = t;
        this.inputContainer.style.display = t ? "none" : "block"
    }
};
var qi = class extends g {
    setup() {
        this.container = this.$el, this.type = this.$opts.type, this.textElem = this.container.querySelector("span"), this.autoHide = this.$opts.autoHide === "true", this.initialShow = this.$opts.show === "true", this.container.style.display = "grid", window.$events.listen(this.type, t => {
            this.show(t)
        }), this.container.addEventListener("click", this.hide.bind(this)), this.initialShow && setTimeout(() => this.show(this.textElem.textContent), 100), this.hideCleanup = this.hideCleanup.bind(this)
    }
    show(t = "") {
        if (this.container.removeEventListener("transitionend", this.hideCleanup), this.textElem.textContent = t, this.container.style.display = "grid", setTimeout(() => {
                this.container.classList.add("showing")
            }, 1), this.autoHide) {
            let e = t.split(" ").length,
                i = Math.max(2e3, 1e3 + 250 * e);
            setTimeout(this.hide.bind(this), i)
        }
    }
    hide() {
        this.container.classList.remove("showing"), this.container.addEventListener("transitionend", this.hideCleanup)
    }
    hideCleanup() {
        this.container.style.display = "none", this.container.removeEventListener("transitionend", this.hideCleanup)
    }
};
var Bi = class extends g {
    setup() {
        this.removeButton = this.$refs.remove, this.showButton = this.$refs.show, this.input = this.$refs.input, this.setupListeners()
    }
    setupListeners() {
        R(this.removeButton, () => {
            this.input.value = "", this.input.classList.add("hidden"), this.removeButton.classList.add("hidden"), this.showButton.classList.remove("hidden")
        }), R(this.showButton, () => {
            this.input.classList.remove("hidden"), this.removeButton.classList.remove("hidden"), this.showButton.classList.add("hidden")
        })
    }
};
var Pi = class extends g {
    setup() {
        this.commentId = this.$opts.commentId, this.commentLocalId = this.$opts.commentLocalId, this.commentParentId = this.$opts.commentParentId, this.deletedText = this.$opts.deletedText, this.updatedText = this.$opts.updatedText, this.container = this.$el, this.contentContainer = this.$refs.contentContainer, this.form = this.$refs.form, this.formCancel = this.$refs.formCancel, this.editButton = this.$refs.editButton, this.deleteButton = this.$refs.deleteButton, this.replyButton = this.$refs.replyButton, this.input = this.$refs.input, this.setupListeners()
    }
    setupListeners() {
        this.replyButton && this.replyButton.addEventListener("click", () => this.$emit("reply", {
            id: this.commentLocalId,
            element: this.container
        })), this.editButton && (this.editButton.addEventListener("click", this.startEdit.bind(this)), this.form.addEventListener("submit", this.update.bind(this)), this.formCancel.addEventListener("click", () => this.toggleEditMode(!1))), this.deleteButton && this.deleteButton.addEventListener("click", this.delete.bind(this))
    }
    toggleEditMode(t) {
        this.contentContainer.toggleAttribute("hidden", t), this.form.toggleAttribute("hidden", !t)
    }
    startEdit() {
        this.toggleEditMode(!0);
        let t = this.$refs.input.value.split(`
`).length;
        this.$refs.input.style.height = `${t*20+40}px`
    }
    async update(t) {
        t.preventDefault();
        let e = this.showLoading();
        this.form.toggleAttribute("hidden", !0);
        let i = {
            text: this.input.value,
            parent_id: this.parentId || null
        };
        try {
            let r = await window.$http.put(`/comment/${this.commentId}`, i),
                o = _t(r.data);
            this.container.replaceWith(o), window.$events.success(this.updatedText)
        } catch (r) {
            console.error(r), window.$events.showValidationErrors(r), this.form.toggleAttribute("hidden", !1), e.remove()
        }
    }
    async delete() {
        this.showLoading(), await window.$http.delete(`/comment/${this.commentId}`), this.container.closest(".comment-branch").remove(), window.$events.success(this.deletedText), this.$emit("delete")
    }
    showLoading() {
        let t = ae();
        return t.classList.add("px-l"), this.container.append(t), t
    }
};
var Oi = class extends g {
    setup() {
        this.elem = this.$el, this.pageId = Number(this.$opts.pageId), this.container = this.$refs.commentContainer, this.commentCountBar = this.$refs.commentCountBar, this.commentsTitle = this.$refs.commentsTitle, this.addButtonContainer = this.$refs.addButtonContainer, this.replyToRow = this.$refs.replyToRow, this.formContainer = this.$refs.formContainer, this.form = this.$refs.form, this.formInput = this.$refs.formInput, this.formReplyLink = this.$refs.formReplyLink, this.addCommentButton = this.$refs.addCommentButton, this.hideFormButton = this.$refs.hideFormButton, this.removeReplyToButton = this.$refs.removeReplyToButton, this.createdText = this.$opts.createdText, this.countText = this.$opts.countText, this.parentId = null, this.formReplyText = this.formReplyLink?.textContent || "", this.setupListeners()
    }
    setupListeners() {
        this.elem.addEventListener("page-comment-delete", () => {
            this.updateCount(), this.hideForm()
        }), this.elem.addEventListener("page-comment-reply", t => {
            this.setReply(t.detail.id, t.detail.element)
        }), this.form && (this.removeReplyToButton.addEventListener("click", this.removeReplyTo.bind(this)), this.hideFormButton.addEventListener("click", this.hideForm.bind(this)), this.addCommentButton.addEventListener("click", this.showForm.bind(this)), this.form.addEventListener("submit", this.saveComment.bind(this)))
    }
    saveComment(t) {
        t.preventDefault(), t.stopPropagation();
        let e = ae();
        e.classList.add("px-l"), this.form.after(e), this.form.toggleAttribute("hidden", !0);
        let r = {
            text: this.formInput.value,
            parent_id: this.parentId || null
        };
        window.$http.post(`/comment/${this.pageId}`, r).then(o => {
            let s = _t(o.data);
            this.formContainer.after(s), window.$events.success(this.createdText), this.hideForm(), this.updateCount()
        }).catch(o => {
            this.form.toggleAttribute("hidden", !1), window.$events.showValidationErrors(o)
        }), this.form.toggleAttribute("hidden", !1), e.remove()
    }
    updateCount() {
        let t = this.getCommentCount();
        this.commentsTitle.textContent = window.trans_plural(this.countText, t, {
            count: t
        })
    }
    resetForm() {
        this.formInput.value = "", this.parentId = null, this.replyToRow.toggleAttribute("hidden", !0), this.container.append(this.formContainer)
    }
    showForm() {
        this.formContainer.toggleAttribute("hidden", !1), this.addButtonContainer.toggleAttribute("hidden", !0), this.formContainer.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        }), setTimeout(() => {
            this.formInput.focus()
        }, 100)
    }
    hideForm() {
        this.resetForm(), this.formContainer.toggleAttribute("hidden", !0), this.getCommentCount() > 0 ? this.elem.append(this.addButtonContainer) : this.commentCountBar.append(this.addButtonContainer), this.addButtonContainer.toggleAttribute("hidden", !1)
    }
    getCommentCount() {
        return this.container.querySelectorAll('[component="page-comment"]').length
    }
    setReply(t, e) {
        e.closest(".comment-branch").querySelector(".comment-branch-children").append(this.formContainer), this.showForm(), this.parentId = t, this.replyToRow.toggleAttribute("hidden", !1), this.formReplyLink.textContent = this.formReplyText.replace("1234", this.parentId), this.formReplyLink.href = `#comment${this.parentId}`
    }
    removeReplyTo() {
        this.parentId = null, this.replyToRow.toggleAttribute("hidden", !0), this.container.append(this.formContainer), this.showForm()
    }
};

function Bf(n, t) {
    yr(`#page-navigation a[href="#${n}"]`, e => {
        e.closest("li").classList.toggle("current-heading", t)
    })
}

function Pf(n) {
    for (let t of n) {
        let e = t.intersectionRatio === 1;
        Bf(t.target.id, e)
    }
}

function Of(n) {
    let t = {
            rootMargin: "0px 0px 0px 0px",
            threshold: 1
        },
        e = new IntersectionObserver(Pf, t);
    for (let i of n) e.observe(i)
}
var Ri = class extends g {
    setup() {
        if (this.container = this.$el, this.pageId = this.$opts.pageId, window.importVersioned("code").then(e => e.highlight()), this.setupNavHighlighting(), window.location.hash) {
            let e = window.location.hash.replace(/%20/g, " ").substring(1);
            this.goToText(e)
        }
        let t = document.querySelector(".sidebar-page-nav");
        t && K(t, "a", "click", (e, i) => {
            e.preventDefault(), window.$components.first("tri-layout").showContent();
            let r = i.getAttribute("href").substr(1);
            this.goToText(r), window.history.pushState(null, null, `#${r}`)
        })
    }
    goToText(t) {
        let e = document.getElementById(t);
        if (yr(".page-content [data-highlighted]", i => {
                i.removeAttribute("data-highlighted"), i.style.backgroundColor = null
            }), e !== null) kr(e);
        else {
            let i = Qo(".page-content > div > *", t);
            i && kr(i)
        }
    }
    setupNavHighlighting() {
        let t = document.querySelector(".sidebar-page-nav"),
            e = document.querySelector(".page-content").querySelectorAll("h1, h2, h3, h4, h5, h6");
        e.length > 0 && t !== null && Of(e)
    }
};

function iu(n) {
    let t = new Date(n * 1e3),
        e = t.getHours(),
        i = t.getMinutes();
    return `${(e>9?"":"0")+e}:${(i>9?"":"0")+i}`
}
var Ni = class extends g {
    setup() {
        this.draftsEnabled = this.$opts.draftsEnabled === "true", this.editorType = this.$opts.editorType, this.pageId = Number(this.$opts.pageId), this.isNewDraft = this.$opts.pageNewDraft === "true", this.hasDefaultTitle = this.$opts.hasDefaultTitle || !1, this.container = this.$el, this.titleElem = this.$refs.titleContainer.querySelector("input"), this.saveDraftButton = this.$refs.saveDraft, this.discardDraftButton = this.$refs.discardDraft, this.discardDraftWrap = this.$refs.discardDraftWrap, this.deleteDraftButton = this.$refs.deleteDraft, this.deleteDraftWrap = this.$refs.deleteDraftWrap, this.draftDisplay = this.$refs.draftDisplay, this.draftDisplayIcon = this.$refs.draftDisplayIcon, this.changelogInput = this.$refs.changelogInput, this.changelogDisplay = this.$refs.changelogDisplay, this.changeEditorButtons = this.$manyRefs.changeEditor || [], this.switchDialogContainer = this.$refs.switchDialog, this.deleteDraftDialogContainer = this.$refs.deleteDraftDialog, this.draftText = this.$opts.draftText, this.autosaveFailText = this.$opts.autosaveFailText, this.editingPageText = this.$opts.editingPageText, this.draftDiscardedText = this.$opts.draftDiscardedText, this.draftDeleteText = this.$opts.draftDeleteText, this.draftDeleteFailText = this.$opts.draftDeleteFailText, this.setChangelogText = this.$opts.setChangelogText, this.autoSave = {
            interval: null,
            frequency: 3e4,
            last: 0,
            pendingChange: !1
        }, this.shownWarningsCache = new Set, this.pageId !== 0 && this.draftsEnabled && window.setTimeout(() => {
            this.startAutoSave()
        }, 1e3), this.draftDisplay.innerHTML = this.draftText, this.setupListeners(), this.setInitialFocus()
    }
    setupListeners() {
        window.$events.listen("editor-save-draft", this.saveDraft.bind(this)), window.$events.listen("editor-save-page", this.savePage.bind(this));
        let t = () => {
            this.autoSave.pendingChange = !0
        };
        window.$events.listen("editor-html-change", t), window.$events.listen("editor-markdown-change", t), this.titleElem.addEventListener("input", t);
        let e = Nt(this.updateChangelogDisplay.bind(this), 300, !1);
        this.changelogInput.addEventListener("input", e), R(this.saveDraftButton, this.saveDraft.bind(this)), R(this.discardDraftButton, this.discardDraft.bind(this)), R(this.deleteDraftButton, this.deleteDraft.bind(this)), R(this.changeEditorButtons, this.changeEditor.bind(this))
    }
    setInitialFocus() {
        if (this.hasDefaultTitle) {
            this.titleElem.select();
            return
        }
        window.setTimeout(() => {
            window.$events.emit("editor::focus", "")
        }, 500)
    }
    startAutoSave() {
        this.autoSave.interval = window.setInterval(this.runAutoSave.bind(this), this.autoSave.frequency)
    }
    runAutoSave() {
        Date.now() - this.autoSave.last < this.autoSave.frequency / 2 || !this.autoSave.pendingChange || this.saveDraft()
    }
    savePage() {
        this.container.closest("form").submit()
    }
    async saveDraft() {
        let t = {
                name: this.titleElem.value.trim()
            },
            e = this.getEditorComponent().getContent();
        Object.assign(t, e);
        let i = !1;
        try {
            let r = await window.$http.put(`/ajax/page/${this.pageId}/save-draft`, t);
            this.isNewDraft || (this.discardDraftWrap.toggleAttribute("hidden", !1), this.deleteDraftWrap.toggleAttribute("hidden", !1)), this.draftNotifyChange(`${r.data.message} ${iu(r.data.timestamp)}`), this.autoSave.last = Date.now(), r.data.warning && !this.shownWarningsCache.has(r.data.warning) && (window.$events.emit("warning", r.data.warning), this.shownWarningsCache.add(r.data.warning)), i = !0, this.autoSave.pendingChange = !1
        } catch {
            try {
                let o = `draft-save-fail-${new Date().toISOString()}`;
                window.localStorage.setItem(o, JSON.stringify(t))
            } catch (o) {
                console.error(o)
            }
            window.$events.emit("error", this.autosaveFailText)
        }
        return i
    }
    draftNotifyChange(t) {
        this.draftDisplay.innerText = t, this.draftDisplayIcon.classList.add("visible"), window.setTimeout(() => {
            this.draftDisplayIcon.classList.remove("visible")
        }, 2e3)
    }
    async discardDraft(t = !0) {
        let e;
        try {
            e = await window.$http.get(`/ajax/page/${this.pageId}`)
        } catch (i) {
            console.error(i);
            return
        }
        this.autoSave.interval && window.clearInterval(this.autoSave.interval), this.draftDisplay.innerText = this.editingPageText, this.discardDraftWrap.toggleAttribute("hidden", !0), window.$events.emit("editor::replace", {
            html: e.data.html,
            markdown: e.data.markdown
        }), this.titleElem.value = e.data.name, window.setTimeout(() => {
            this.startAutoSave()
        }, 1e3), t && window.$events.success(this.draftDiscardedText)
    }
    async deleteDraft() {
        if (await window.$components.firstOnElement(this.deleteDraftDialogContainer, "confirm-dialog").show()) try {
            let i = this.discardDraft(!1),
                r = window.$http.delete(`/page-revisions/user-drafts/${this.pageId}`);
            await Promise.all([i, r]), window.$events.success(this.draftDeleteText), this.deleteDraftWrap.toggleAttribute("hidden", !0)
        } catch (i) {
            console.error(i), window.$events.error(this.draftDeleteFailText)
        }
    }
    updateChangelogDisplay() {
        let t = this.changelogInput.value.trim();
        t.length === 0 ? t = this.setChangelogText : t.length > 16 && (t = `${t.slice(0,16)}...`), this.changelogDisplay.innerText = t
    }
    async changeEditor(t) {
        t.preventDefault();
        let e = t.target.closest("a").href,
            i = window.$components.firstOnElement(this.switchDialogContainer, "confirm-dialog"),
            [r, o] = await Promise.all([this.saveDraft(), i.show()]);
        r && o && (window.location = e)
    }
    getEditorComponent() {
        return window.$components.first("markdown-editor") || window.$components.first("wysiwyg-editor")
    }
};

function zi(n, t) {
    n.style.display = t ? null : "none"
}
var Hi = class extends g {
    setup() {
        this.input = this.$refs.input, this.resetButton = this.$refs.resetButton, this.selectButton = this.$refs.selectButton, this.display = this.$refs.display, this.defaultDisplay = this.$refs.defaultDisplay, this.buttonSep = this.$refs.buttonSeperator, this.value = this.input.value, this.setupListeners()
    }
    setupListeners() {
        this.selectButton.addEventListener("click", this.showPopup.bind(this)), this.display.parentElement.addEventListener("click", this.showPopup.bind(this)), this.resetButton.addEventListener("click", () => {
            this.setValue("", "")
        })
    }
    showPopup() {
        window.$components.first("entity-selector-popup").show(e => {
            this.setValue(e.id, e.name)
        })
    }
    setValue(t, e) {
        this.value = t, this.input.value = t, this.controlView(e)
    }
    controlView(t) {
        let e = this.value && this.value !== 0;
        if (zi(this.resetButton, e), zi(this.buttonSep, e), zi(this.defaultDisplay, !e), zi(this.display, e), e) {
            let i = this.getAssetIdFromVal();
            this.display.textContent = `#${i}, ${t}`, this.display.href = window.baseUrl(`/link/${i}`)
        }
    }
    getAssetIdFromVal() {
        return Number(this.value)
    }
};
var Ui = class extends g {
    setup() {
        this.container = this.$el, this.cellSelector = this.$opts.cellSelector || "td,th", this.rowSelector = this.$opts.rowSelector || "tr";
        for (let t of this.$manyRefs.toggleAll || []) t.addEventListener("click", this.toggleAllClick.bind(this));
        for (let t of this.$manyRefs.toggleRow || []) t.addEventListener("click", this.toggleRowClick.bind(this));
        for (let t of this.$manyRefs.toggleColumn || []) t.addEventListener("click", this.toggleColumnClick.bind(this))
    }
    toggleAllClick(t) {
        t.preventDefault(), this.toggleAllInElement(this.container)
    }
    toggleRowClick(t) {
        t.preventDefault(), this.toggleAllInElement(t.target.closest(this.rowSelector))
    }
    toggleColumnClick(t) {
        t.preventDefault();
        let e = t.target.closest(this.cellSelector),
            i = Array.from(e.parentElement.children).indexOf(e),
            r = this.container.querySelectorAll(this.rowSelector),
            o = [];
        for (let s of r) {
            let a = s.children[i];
            a && o.push(...a.querySelectorAll("input[type=checkbox]"))
        }
        this.toggleAllInputs(o)
    }
    toggleAllInElement(t) {
        let e = t.querySelectorAll("input[type=checkbox]");
        this.toggleAllInputs(e)
    }
    toggleAllInputs(t) {
        let e = t.length > 0 ? t[0].checked : !1;
        for (let i of t) i.checked = !e, i.dispatchEvent(new Event("change"))
    }
};
var ji = class extends g {
    setup() {
        this.container = this.$el, this.pointer = this.$refs.pointer, this.linkInput = this.$refs.linkInput, this.linkButton = this.$refs.linkButton, this.includeInput = this.$refs.includeInput, this.includeButton = this.$refs.includeButton, this.sectionModeButton = this.$refs.sectionModeButton, this.modeToggles = this.$manyRefs.modeToggle, this.modeSections = this.$manyRefs.modeSection, this.pageId = this.$opts.pageId, this.showing = !1, this.isSelection = !1, this.setupListeners()
    }
    setupListeners() {
        this.includeButton.addEventListener("click", () => Vr(this.includeInput.value)), this.linkButton.addEventListener("click", () => Vr(this.linkInput.value)), R([this.includeInput, this.linkInput], e => {
            e.target.select(), e.stopPropagation()
        }), ln(this.pointer, ["click", "focus"], e => {
            e.stopPropagation()
        }), ln(document.body, ["click", "focus"], () => {
            !this.showing || this.isSelection || this.hidePointer()
        }), Jo(this.pointer, this.hidePointer.bind(this));
        let t = document.querySelector(".page-content");
        ln(t, ["mouseup", "keyup"], e => {
            e.stopPropagation();
            let i = e.target.closest('[id^="bkmrk"]');
            i && window.getSelection().toString().length > 0 && this.showPointerAtTarget(i, e.pageX, !1)
        }), R(this.sectionModeButton, this.enterSectionSelectMode.bind(this)), R(this.modeToggles, e => {
            for (let i of this.modeSections) {
                let r = !i.contains(e.target);
                i.toggleAttribute("hidden", !r)
            }
            this.modeToggles.find(i => i !== e.target).focus()
        })
    }
    hidePointer() {
        this.pointer.style.display = null, this.showing = !1
    }
    showPointerAtTarget(t, e, i) {
        this.updateForTarget(t), this.pointer.style.display = "block";
        let r = t.getBoundingClientRect(),
            o = this.pointer.getBoundingClientRect(),
            a = Math.min(Math.max(e, r.left), r.right) - o.width / 2,
            l = r.top - o.height - 16;
        this.pointer.style.left = `${a}px`, this.pointer.style.top = `${l}px`, this.showing = !0, this.isSelection = !0, setTimeout(() => {
            this.isSelection = !1
        }, 100);
        let c = () => {
            this.hidePointer(), window.removeEventListener("scroll", c, {
                passive: !0
            })
        };
        t.parentElement.insertBefore(this.pointer, t), i || window.addEventListener("scroll", c, {
            passive: !0
        })
    }
    updateForTarget(t) {
        let e = window.baseUrl(`/link/${this.pageId}#${t.id}`),
            i = `{{@${this.pageId}#${t.id}}}`;
        this.linkInput.value = e, this.includeInput.value = i;
        let r = this.pointer.querySelector("#pointer-edit");
        if (r && t) {
            let {
                editHref: o
            } = r.dataset, s = t.id, a = t.textContent && t.textContent.substring(0, 50);
            r.href = `${o}?content-id=${s}&content-text=${encodeURIComponent(a)}`
        }
    }
    enterSectionSelectMode() {
        let t = Array.from(document.querySelectorAll('.page-content [id^="bkmrk"]'));
        for (let e of t) e.setAttribute("tabindex", "0");
        t[0].focus(), se(t, e => {
            this.showPointerAtTarget(e.target, 0, !0), this.pointer.focus()
        })
    }
};
var Vi = class extends g {
    setup() {
        this.container = this.$el, this.hideButtons = this.$manyRefs.hide || [], this.onkeyup = null, this.onHide = null, this.setupListeners()
    }
    setupListeners() {
        let t = null;
        this.container.addEventListener("mousedown", e => {
            t = e.target
        }), this.container.addEventListener("click", e => {
            e.target === this.container && t === this.container && this.hide()
        }), R(this.hideButtons, () => this.hide())
    }
    hide(t = null) {
        Ts(this.container, 120, t), this.onkeyup && (window.removeEventListener("keyup", this.onkeyup), this.onkeyup = null), this.onHide && this.onHide()
    }
    show(t = null, e = null) {
        Ls(this.container, 120, t), this.onkeyup = i => {
            i.key === "Escape" && this.hide()
        }, window.addEventListener("keyup", this.onkeyup), this.onHide = e
    }
};
var Wi = class extends g {
    setup() {
        this.container = this.$el, this.mode = this.$opts.mode, this.lightContainer = this.$refs.lightContainer, this.darkContainer = this.$refs.darkContainer, this.container.addEventListener("tabs-change", e => {
            let r = e.detail.showing === "color-scheme-panel-light" ? "light" : "dark";
            this.handleModeChange(r)
        });
        let t = e => {
            this.updateAppColorsFromInputs(), e.target.name.startsWith("setting-app-color") && this.updateLightForInput(e.target)
        };
        this.container.addEventListener("change", t), this.container.addEventListener("input", t)
    }
    handleModeChange(t) {
        this.mode = t;
        let e = t === "dark";
        document.documentElement.classList.toggle("dark-mode", e), this.updateAppColorsFromInputs()
    }
    updateAppColorsFromInputs() {
        let e = (this.mode === "dark" ? this.darkContainer : this.lightContainer).querySelectorAll('input[type="color"]');
        for (let i of e) {
            let r = i.name.split("-"),
                o = r.indexOf("color"),
                s = r.slice(1, o).join("-");
            s === "app" && (s = "primary");
            let a = `--color-${s}`;
            document.body.style.setProperty(a, i.value)
        }
    }
    updateLightForInput(t) {
        let e = t.name.replace("-color", "-color-light"),
            i = t.value,
            r = this.hexToRgb(i),
            o = `rgba(${[r.r,r.g,r.b,"0.15"].join(",")})`,
            s = this.container.querySelector(`input[name="${e}"][type="hidden"]`);
        s.value = o
    }
    hexToRgb(t) {
        let e = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(t);
        return {
            r: e ? parseInt(e[1], 16) : 0,
            g: e ? parseInt(e[2], 16) : 0,
            b: e ? parseInt(e[3], 16) : 0
        }
    }
};
var Gi = class extends g {
    setup() {
        this.colorInput = this.$refs.input, this.resetButton = this.$refs.resetButton, this.defaultButton = this.$refs.defaultButton, this.currentColor = this.$opts.current, this.defaultColor = this.$opts.default, this.resetButton.addEventListener("click", () => this.setValue(this.currentColor)), this.defaultButton.addEventListener("click", () => this.setValue(this.defaultColor))
    }
    setValue(t) {
        this.colorInput.value = t, this.colorInput.dispatchEvent(new Event("change", {
            bubbles: !0
        }))
    }
};
var Ki = class extends g {
    setup() {
        this.typeControl = this.$refs.typeControl, this.pagePickerContainer = this.$refs.pagePickerContainer, this.typeControl.addEventListener("change", this.controlPagePickerVisibility.bind(this)), this.controlPagePickerVisibility()
    }
    controlPagePickerVisibility() {
        let t = this.typeControl.value === "page";
        this.pagePickerContainer.style.display = t ? "block" : "none"
    }
};
var Nf = {
        move_up(n) {
            let t = n.parentNode,
                e = Array.from(t.children).indexOf(n),
                i = Math.max(e - 1, 0);
            t.insertBefore(n, t.children[i] || null)
        },
        move_down(n) {
            let t = n.parentNode,
                e = Array.from(t.children).indexOf(n),
                i = Math.min(e + 2, t.children.length);
            t.insertBefore(n, t.children[i] || null)
        },
        remove(n, t, e) {
            e.appendChild(n)
        },
        add(n, t) {
            t.appendChild(n)
        }
    },
    Zi = class extends g {
        setup() {
            this.elem = this.$el, this.input = this.$refs.input, this.shelfBookList = this.$refs.shelfBookList, this.allBookList = this.$refs.allBookList, this.bookSearchInput = this.$refs.bookSearch, this.sortButtonContainer = this.$refs.sortButtonContainer, this.lastSort = null, this.initSortable(), this.setupListeners()
        }
        initSortable() {
            let t = this.elem.querySelectorAll(".scroll-box");
            for (let e of t) new Yt(e, {
                group: "shelf-books",
                ghostClass: "primary-background-light",
                handle: ".handle",
                animation: 150,
                onSort: this.onChange.bind(this)
            })
        }
        setupListeners() {
            this.elem.addEventListener("click", t => {
                let e = t.target.closest(".scroll-box-item button[data-action]");
                e && this.sortItemActionClick(e)
            }), this.bookSearchInput.addEventListener("input", () => {
                this.filterBooksByName(this.bookSearchInput.value)
            }), this.sortButtonContainer.addEventListener("click", t => {
                let e = t.target.closest("button[data-sort]");
                e && this.sortShelfBooks(e.dataset.sort)
            })
        }
        filterBooksByName(t) {
            this.allBookList.style.height || (this.allBookList.style.height = `${this.allBookList.getBoundingClientRect().height}px`);
            let e = this.allBookList.children,
                i = t.trim().toLowerCase();
            for (let r of e) {
                let o = !t || r.textContent.toLowerCase().includes(i);
                r.style.display = o ? null : "none"
            }
        }
        sortItemActionClick(t) {
            let e = t.closest(".scroll-box-item"),
                {
                    action: i
                } = t.dataset,
                r = Nf[i];
            r(e, this.shelfBookList, this.allBookList), this.onChange()
        }
        onChange() {
            let t = Array.from(this.shelfBookList.querySelectorAll("[data-id]"));
            this.input.value = t.map(e => e.getAttribute("data-id")).join(",")
        }
        sortShelfBooks(t) {
            let e = Array.from(this.shelfBookList.children),
                i = t === this.lastSort;
            e.sort((r, o) => {
                let s = r.dataset[t].toLowerCase(),
                    a = o.dataset[t].toLowerCase();
                return i ? a.localeCompare(s) : s.localeCompare(a)
            });
            for (let r of e) this.shelfBookList.append(r);
            this.lastSort = this.lastSort === t ? null : t, this.onChange()
        }
    };

function zf(n) {
    let t = {};
    for (let [e, i] of Object.entries(n)) t[i] = e;
    return t
}
var Xi = class extends g {
    setup() {
        this.container = this.$el, this.mapById = JSON.parse(this.$opts.keyMap), this.mapByShortcut = zf(this.mapById), this.hintsShowing = !1, this.hideHints = this.hideHints.bind(this), this.hintAbortController = null, this.setupListeners()
    }
    setupListeners() {
        window.addEventListener("keydown", t => {
            if (!t.target.closest("input, select, textarea, .cm-editor")) {
                if (t.key === "?") {
                    this.hintsShowing ? this.hideHints() : this.showHints();
                    return
                }
                this.handleShortcutPress(t)
            }
        })
    }
    handleShortcutPress(t) {
        let i = [t.ctrlKey ? "Ctrl" : "", t.metaKey ? "Cmd" : "", t.key].filter(o => !!o).join(" + "),
            r = this.mapByShortcut[i];
        r && this.runShortcut(r) && t.preventDefault()
    }
    runShortcut(t) {
        let e = this.container.querySelector(`[data-shortcut="${t}"]`);
        return e ? e.matches("input, textarea, select") ? (e.focus(), !0) : e.matches("a, button") ? (e.click(), !0) : e.matches("div[tabindex]") ? (e.click(), e.focus(), !0) : (console.error("Shortcut attempted to be ran for element type that does not have handling setup", e), !1) : !1
    }
    showHints() {
        let t = document.createElement("div");
        t.classList.add("shortcut-container"), this.container.append(t);
        let e = this.container.querySelectorAll("[data-shortcut]"),
            i = new Set;
        for (let o of e) {
            let s = o.getAttribute("data-shortcut");
            if (i.has(s)) continue;
            let a = this.mapById[s];
            this.showHintLabel(o, a, t), i.add(s)
        }
        this.hintAbortController = new AbortController;
        let r = this.hintAbortController.signal;
        window.addEventListener("scroll", this.hideHints, {
            signal: r
        }), window.addEventListener("focus", this.hideHints, {
            signal: r
        }), window.addEventListener("blur", this.hideHints, {
            signal: r
        }), window.addEventListener("click", this.hideHints, {
            signal: r
        }), this.hintsShowing = !0
    }
    showHintLabel(t, e, i) {
        let r = t.getBoundingClientRect(),
            o = document.createElement("div");
        o.classList.add("shortcut-hint"), o.textContent = e;
        let s = document.createElement("div");
        s.classList.add("shortcut-linkage"), s.style.left = `${r.x}px`, s.style.top = `${r.y}px`, s.style.width = `${r.width}px`, s.style.height = `${r.height}px`, i.append(o, s);
        let a = o.getBoundingClientRect();
        o.style.insetInlineStart = `${r.x+r.width-(a.width+6)}px`, o.style.insetBlockStart = `${r.y+(r.height-a.height)/2}px`
    }
    hideHints() {
        this.container.querySelector(".shortcut-container").remove(), this.hintAbortController?.abort(), this.hintsShowing = !1
    }
};
var Hf = ["Control", "Alt", "Shift", "Meta", "Super", " ", "+", "Tab", "Escape"],
    Yi = class extends g {
        setup() {
            this.input = this.$el, this.setupListeners()
        }
        setupListeners() {
            this.listenerRecordKey = this.listenerRecordKey.bind(this), this.input.addEventListener("focus", () => {
                this.startListeningForInput()
            }), this.input.addEventListener("blur", () => {
                this.stopListeningForInput()
            })
        }
        startListeningForInput() {
            this.input.addEventListener("keydown", this.listenerRecordKey)
        }
        listenerRecordKey(t) {
            if (Hf.includes(t.key)) return;
            let e = [t.ctrlKey ? "Ctrl" : "", t.metaKey ? "Cmd" : "", t.key];
            this.input.value = e.filter(i => !!i).join(" + ")
        }
        stopListeningForInput() {
            this.input.removeEventListener("keydown", this.listenerRecordKey)
        }
    };
var Ji = class extends g {
    setup() {
        this.container = this.$el, this.handleSelector = this.$opts.handleSelector;
        let t = new Yt(this.container, {
            handle: this.handleSelector,
            animation: 150,
            onSort: () => {
                this.$emit("sort", {
                    ids: t.toArray()
                })
            },
            setData(e, i) {
                let r = i.getAttribute("data-drag-content");
                if (r) {
                    let o = JSON.parse(r);
                    for (let [s, a] of Object.entries(o)) e.setData(s, a)
                }
            },
            revertOnSpill: !0,
            dropBubble: !0,
            dragoverBubble: !1
        })
    }
};
var Qi = class extends g {
    setup() {
        this.filter = this.$opts.filter, this.$el.addEventListener("change", t => {
            if (this.filter && !t.target.matches(this.filter)) return;
            let e = this.$el.closest("form");
            e && e.submit()
        })
    }
};
var tr = class extends g {
    setup() {
        this.container = this.$el, this.tabList = this.container.querySelector('[role="tablist"]'), this.tabs = Array.from(this.tabList.querySelectorAll('[role="tab"]')), this.panels = Array.from(this.container.querySelectorAll(':scope > [role="tabpanel"], :scope > * > [role="tabpanel"]')), this.activeUnder = this.$opts.activeUnder ? Number(this.$opts.activeUnder) : 1e4, this.active = null, this.container.addEventListener("click", t => {
            let e = t.target.closest('[role="tab"]');
            e && this.tabs.includes(e) && this.show(e.getAttribute("aria-controls"))
        }), window.addEventListener("resize", this.updateActiveState.bind(this), {
            passive: !0
        }), this.updateActiveState()
    }
    show(t) {
        for (let e of this.panels) e.toggleAttribute("hidden", e.id !== t);
        for (let e of this.tabs) {
            let r = e.getAttribute("aria-controls") === t;
            e.setAttribute("aria-selected", r ? "true" : "false")
        }
        this.$emit("change", {
            showing: t
        })
    }
    updateActiveState() {
        let t = window.innerWidth < this.activeUnder;
        t !== this.active && (t ? this.activate() : this.deactivate(), this.active = t)
    }
    activate() {
        let t = this.panels.find(e => !e.hasAttribute("hidden")) || this.panels[0];
        this.show(t.id), this.tabList.toggleAttribute("hidden", !1)
    }
    deactivate() {
        for (let t of this.panels) t.removeAttribute("hidden");
        for (let t of this.tabs) t.setAttribute("aria-selected", "false");
        this.tabList.toggleAttribute("hidden", !0)
    }
};
var er = class extends g {
    setup() {
        this.addRemoveComponentEl = this.$refs.addRemove, this.container = this.$el, this.rowSelector = this.$opts.rowSelector, this.setupListeners()
    }
    setupListeners() {
        this.container.addEventListener("input", t => {
            let e = window.$components.firstOnElement(this.addRemoveComponentEl, "add-remove-rows");
            !this.hasEmptyRows() && t.target.value && e.add()
        })
    }
    hasEmptyRows() {
        return [...this.container.querySelectorAll(this.rowSelector)].find(i => [...i.querySelectorAll("input")].filter(r => r.value).length === 0) !== void 0
    }
};
var nr = class extends g {
    setup() {
        this.container = this.$el, this.list = this.$refs.list, this.searchInput = this.$refs.searchInput, this.searchButton = this.$refs.searchButton, this.searchCancel = this.$refs.searchCancel, this.setupListeners()
    }
    setupListeners() {
        K(this.container, "[template-action]", "click", this.handleTemplateActionClick.bind(this)), K(this.container, ".pagination a", "click", this.handlePaginationClick.bind(this)), K(this.container, ".template-item-content", "click", this.handleTemplateItemClick.bind(this)), K(this.container, ".template-item", "dragstart", this.handleTemplateItemDragStart.bind(this)), this.searchInput.addEventListener("keypress", t => {
            t.key === "Enter" && (t.preventDefault(), this.performSearch())
        }), this.searchButton.addEventListener("click", () => this.performSearch()), this.searchCancel.addEventListener("click", () => {
            this.searchInput.value = "", this.performSearch()
        })
    }
    handleTemplateItemClick(t, e) {
        let i = e.closest("[template-id]").getAttribute("template-id");
        this.insertTemplate(i, "replace")
    }
    handleTemplateItemDragStart(t, e) {
        let i = e.closest("[template-id]").getAttribute("template-id");
        t.dataTransfer.setData("bookstack/template", i), t.dataTransfer.setData("text/plain", i)
    }
    handleTemplateActionClick(t, e) {
        t.stopPropagation();
        let i = e.getAttribute("template-action"),
            r = e.closest("[template-id]").getAttribute("template-id");
        this.insertTemplate(r, i)
    }
    async insertTemplate(t, e = "replace") {
        let i = await window.$http.get(`/templates/${t}`),
            r = `editor::${e}`;
        window.$events.emit(r, i.data)
    }
    async handlePaginationClick(t, e) {
        t.preventDefault();
        let i = e.getAttribute("href"),
            r = await window.$http.get(i);
        this.list.innerHTML = r.data
    }
    async performSearch() {
        let t = this.searchInput.value,
            e = await window.$http.get("/templates", {
                search: t
            });
        this.searchCancel.style.display = t ? "block" : "none", this.list.innerHTML = e.data
    }
};
var ir = class extends g {
    setup() {
        this.input = this.$el.querySelector("input[type=hidden]"), this.checkbox = this.$el.querySelector("input[type=checkbox]"), this.checkbox.addEventListener("change", this.stateChange.bind(this))
    }
    stateChange() {
        this.input.value = this.checkbox.checked ? "true" : "false";
        let t = new Event("change");
        this.input.dispatchEvent(t)
    }
};
var rr = class extends g {
    setup() {
        this.container = this.$refs.container, this.tabs = this.$manyRefs.tab, this.lastLayoutType = "none", this.onDestroy = null, this.scrollCache = {
            content: 0,
            info: 0
        }, this.lastTabShown = "content", this.mobileTabClick = this.mobileTabClick.bind(this), this.updateLayout(), window.addEventListener("resize", () => {
            this.updateLayout()
        }, {
            passive: !0
        })
    }
    updateLayout() {
        let t = "tablet";
        window.innerWidth <= 1e3 && (t = "mobile"), window.innerWidth >= 1400 && (t = "desktop"), t !== this.lastLayoutType && (this.onDestroy && (this.onDestroy(), this.onDestroy = null), t === "desktop" ? this.setupDesktop() : t === "mobile" && this.setupMobile(), this.lastLayoutType = t)
    }
    setupMobile() {
        for (let t of this.tabs) t.addEventListener("click", this.mobileTabClick);
        this.onDestroy = () => {
            for (let t of this.tabs) t.removeEventListener("click", this.mobileTabClick)
        }
    }
    setupDesktop() {}
    mobileTabClick(t) {
        let {
            tab: e
        } = t.target.dataset;
        this.showTab(e)
    }
    showContent() {
        this.showTab("content", !1)
    }
    showTab(t, e = !0) {
        this.scrollCache[this.lastTabShown] = document.documentElement.scrollTop;
        for (let r of this.tabs) {
            let o = r.dataset.tab === t;
            r.setAttribute("aria-selected", o ? "true" : "false")
        }
        let i = t === "info";
        if (this.container.classList.toggle("show-info", i), e) {
            let o = document.querySelector("header").getBoundingClientRect().bottom;
            document.documentElement.scrollTop = this.scrollCache[t] || o, setTimeout(() => {
                document.documentElement.scrollTop = this.scrollCache[t] || o
            }, 50)
        }
        this.lastTabShown = t
    }
};
var or = class extends g {
    setup() {
        this.container = this.$el, this.input = this.$refs.input, this.userInfoContainer = this.$refs.userInfo, K(this.container, "a.dropdown-search-item", "click", this.selectUser.bind(this))
    }
    selectUser(t, e) {
        t.preventDefault(), this.input.value = e.getAttribute("data-id"), this.userInfoContainer.innerHTML = e.innerHTML, this.input.dispatchEvent(new Event("change", {
            bubbles: !0
        })), this.hide()
    }
    hide() {
        window.$components.firstOnElement(this.container, "dropdown").hide()
    }
};
var sr = class extends g {
    setup() {
        this.checkboxes = this.$el.querySelectorAll('input[type="checkbox"]'), this.allCheckbox = this.$el.querySelector('input[type="checkbox"][value="all"]'), this.$el.addEventListener("change", t => {
            t.target.checked && t.target === this.allCheckbox ? this.deselectIndividualEvents() : t.target.checked && (this.allCheckbox.checked = !1)
        })
    }
    deselectIndividualEvents() {
        for (let t of this.checkboxes) t !== this.allCheckbox && (t.checked = !1)
    }
};

function ru(n) {
    for (let t = 1; t < 5; t++) n.shortcuts.add(`meta+${t}`, "", ["FormatBlock", !1, `h${t+1}`]);
    n.shortcuts.add("meta+5", "", ["FormatBlock", !1, "p"]), n.shortcuts.add("meta+d", "", ["FormatBlock", !1, "p"]), n.shortcuts.add("meta+6", "", ["FormatBlock", !1, "blockquote"]), n.shortcuts.add("meta+q", "", ["FormatBlock", !1, "blockquote"]), n.shortcuts.add("meta+7", "", ["codeeditor", !1, "pre"]), n.shortcuts.add("meta+e", "", ["codeeditor", !1, "pre"]), n.shortcuts.add("meta+8", "", ["FormatBlock", !1, "code"]), n.shortcuts.add("meta+shift+E", "", ["FormatBlock", !1, "code"]), n.shortcuts.add("meta+o", "", "InsertOrderedList"), n.shortcuts.add("meta+p", "", "InsertUnorderedList"), n.shortcuts.add("meta+S", "", () => {
        window.$events.emit("editor-save-draft")
    }), n.shortcuts.add("meta+13", "", () => {
        window.$events.emit("editor-save-page")
    }), n.shortcuts.add("meta+9", "", () => {
        let t = n.selection.getNode(),
            e = t ? t.closest(".callout") : null,
            i = ["info", "success", "warning", "danger"],
            o = (i.findIndex(a => e && e.classList.contains(a)) + 1) % i.length,
            s = i[o];
        n.formatter.apply(`callout${s}`)
    }), n.shortcuts.add("meta+shift+K", "", () => {
        let t = window.$components.first("entity-selector-popup"),
            e = n.selection.getContent({
                format: "text"
            }).trim();
        t.show(i => {
            n.selection.isCollapsed() ? n.insertContent(n.dom.createHTML("a", {
                href: i.link
            }, n.dom.encode(i.name))) : n.formatter.apply("link", {
                href: i.link
            }), n.selection.collapse(!1), n.focus()
        }, e)
    })
}

function ou(n) {
    window.$events.listen("editor::replace", ({
        html: t
    }) => {
        n.setContent(t)
    }), window.$events.listen("editor::append", ({
        html: t
    }) => {
        let e = n.getContent() + t;
        n.setContent(e)
    }), window.$events.listen("editor::prepend", ({
        html: t
    }) => {
        let e = t + n.getContent();
        n.setContent(e)
    }), window.$events.listen("editor::insert", ({
        html: t
    }) => {
        n.insertContent(t)
    }), window.$events.listen("editor::focus", () => {
        n.initialized && n.focus()
    })
}

function Uf(n, t) {
    let e = n.dom.get(encodeURIComponent(t).replace(/!/g, "%21"));
    e && (e.scrollIntoView(), n.selection.select(e, !0), n.selection.collapse(!1), n.focus())
}

function su(n) {
    let e = new URL(window.location).searchParams.get("content-id");
    e && Uf(n, e)
}
var ie, ar;

function jf(n) {
    return n && !!(n.textContent || n.innerText)
}
async function Vf(n, t) {
    if (n === null || n.type.indexOf("image") !== 0) throw new Error("Not an image file");
    let e = n.name || `image-${Date.now()}.png`,
        i = new FormData;
    return i.append("file", n, e), i.append("uploaded_to", t), (await window.$http.post(window.baseUrl("/images/gallery"), i)).data
}

function au(n, t, e) {
    let i = new Ft(e.clipboardData || e.dataTransfer);
    if (!i.hasItems() || i.containsTabularData()) return;
    let r = i.getImages();
    for (let o of r) {
        let s = `image-${Math.random().toString(16).slice(2)}`,
            a = window.baseUrl("/loading.gif");
        e.preventDefault(), setTimeout(() => {
            n.insertContent(`<p><img src="${a}" id="${s}"></p>`), Vf(o, t.pageId).then(l => {
                let c = l.name.replace(/"/g, ""),
                    u = `<img src="${l.thumbs.display}" alt="${c}" />`,
                    h = n.dom.create("a", {
                        target: "_blank",
                        href: l.url
                    }, u);
                n.dom.replace(h, s)
            }).catch(l => {
                n.dom.remove(s), window.$events.error(l?.data?.message || t.translations.imageUploadErrorText), console.error(l)
            })
        }, 10)
    }
}

function Wf(n) {
    let t = n.selection.getNode();
    t.nodeName === "IMG" && (ie = n.dom.getParent(t, ".mceTemp"), !ie && t.parentNode.nodeName === "A" && !jf(t.parentNode) && (ie = t.parentNode)), t.hasAttribute("contenteditable") && t.getAttribute("contenteditable") === "false" && (ar = t)
}

function Gf(n, t, e) {
    let {
        dom: i
    } = n, r = window.tinymce.dom.RangeUtils.getCaretRangeFromPoint(e.clientX, e.clientY, n.getDoc()), o = e.dataTransfer && e.dataTransfer.getData("bookstack/template");
    o && (e.preventDefault(), window.$http.get(`/templates/${o}`).then(s => {
        n.selection.setRng(r), n.undoManager.transact(() => {
            n.execCommand("mceInsertContent", !1, s.data.html)
        })
    })), i.getParent(r.startContainer, ".mceTemp") ? e.preventDefault() : ie && (e.preventDefault(), n.undoManager.transact(() => {
        n.selection.setRng(r), n.selection.setNode(ie), i.remove(ie)
    })), !e.isDefaultPrevented() && ar && (e.preventDefault(), n.undoManager.transact(() => {
        let s = n.selection.getNode(),
            a = n.selection.getRng(),
            l = s.closest("body > *");
        a.startOffset > a.startContainer.length / 2 ? l.after(ar) : l.before(ar)
    })), e.isDefaultPrevented() || au(n, t, e), ie = null
}

function lu(n, t) {
    n.on("dragstart", () => Wf(n)), n.on("drop", e => Gf(n, t, e)), n.on("paste", e => au(n, t, e))
}

function cu(n) {
    return ["undo redo", "styles", "bold italic underline forecolor backcolor formatoverflow", "alignleft aligncenter alignright alignjustify", "bullist numlist listoverflow", n.textDirection === "rtl" ? "ltr rtl" : "", "link table imagemanager-insert insertoverflow", "code about fullscreen"].filter(i => !!i).join(" | ")
}

function Kf(n) {
    n.ui.registry.addGroupToolbarButton("formatoverflow", {
        icon: "more-drawer",
        tooltip: "More",
        items: "strikethrough superscript subscript inlinecode removeformat"
    }), n.ui.registry.addGroupToolbarButton("listoverflow", {
        icon: "more-drawer",
        tooltip: "More",
        items: "tasklist outdent indent"
    }), n.ui.registry.addGroupToolbarButton("insertoverflow", {
        icon: "more-drawer",
        tooltip: "More",
        items: "customhr codeeditor drawio media details"
    })
}

function Zf(n) {
    n.ui.registry.addContextToolbar("linkcontexttoolbar", {
        predicate(t) {
            return t.closest("a") !== null
        },
        position: "node",
        scope: "node",
        items: "link unlink openlink"
    })
}

function Xf(n) {
    n.ui.registry.addContextToolbar("imagecontexttoolbar", {
        predicate(t) {
            return t.closest("img") !== null
        },
        position: "node",
        scope: "node",
        items: "image"
    })
}

function uu(n) {
    Kf(n), Zf(n), Xf(n)
}
var Yf = {
    "table-delete-column": '<svg width="24" height="24"><path d="M21 19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14c1.1 0 2 .9 2 2zm-2 0V5h-4v2.2h-2V5h-2v2.2H9V5H5v14h4v-2.1h2V19h2v-2.1h2V19Z"/><path d="M14.829 10.585 13.415 12l1.414 1.414c.943.943-.472 2.357-1.414 1.414L12 13.414l-1.414 1.414c-.944.944-2.358-.47-1.414-1.414L10.586 12l-1.414-1.415c-.943-.942.471-2.357 1.414-1.414L12 10.585l1.344-1.343c1.111-1.112 2.2.627 1.485 1.343z" style="fill-rule:nonzero"/></svg>',
    "table-delete-row": '<svg width="24" height="24"><path d="M5 21a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14c0 1.1-.9 2-2 2zm0-2h14v-4h-2.2v-2H19v-2h-2.2V9H19V5H5v4h2.1v2H5v2h2.1v2H5Z"/><path d="M13.415 14.829 12 13.415l-1.414 1.414c-.943.943-2.357-.472-1.414-1.414L10.586 12l-1.414-1.414c-.944-.944.47-2.358 1.414-1.414L12 10.586l1.415-1.414c.942-.943 2.357.471 1.414 1.414L13.415 12l1.343 1.344c1.112 1.111-.627 2.2-1.343 1.485z" style="fill-rule:nonzero"/></svg>',
    "table-insert-column-after": '<svg width="24" height="24"><path d="M16 5h-5v14h5c1.235 0 1.234 2 0 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11c1.229 0 1.236 2 0 2zm-7 6V5H5v6zm0 8v-6H5v6zm11.076-6h-2v2c0 1.333-2 1.333-2 0v-2h-2c-1.335 0-1.335-2 0-2h2V9c0-1.333 2-1.333 2 0v2h1.9c1.572 0 1.113 2 .1 2z"/></svg>',
    "table-insert-column-before": '<svg width="24" height="24"><path d="M8 19h5V5H8C6.764 5 6.766 3 8 3h11a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8c-1.229 0-1.236-2 0-2zm7-6v6h4v-6zm0-8v6h4V5ZM3.924 11h2V9c0-1.333 2-1.333 2 0v2h2c1.335 0 1.335 2 0 2h-2v2c0 1.333-2 1.333-2 0v-2h-1.9c-1.572 0-1.113-2-.1-2z"/></svg>',
    "table-insert-row-above": '<svg width="24" height="24"><path d="M5 8v5h14V8c0-1.235 2-1.234 2 0v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8C3 6.77 5 6.764 5 8zm6 7H5v4h6zm8 0h-6v4h6zM13 3.924v2h2c1.333 0 1.333 2 0 2h-2v2c0 1.335-2 1.335-2 0v-2H9c-1.333 0-1.333-2 0-2h2v-1.9c0-1.572 2-1.113 2-.1z"/></svg>',
    "table-insert-row-after": '<svg width="24" height="24"><path d="M19 16v-5H5v5c0 1.235-2 1.234-2 0V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v11c0 1.229-2 1.236-2 0zm-6-7h6V5h-6zM5 9h6V5H5Zm6 11.076v-2H9c-1.333 0-1.333-2 0-2h2v-2c0-1.335 2-1.335 2 0v2h2c1.333 0 1.333 2 0 2h-2v1.9c0 1.572-2 1.113-2 .1z"/></svg>',
    table: '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg"><path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5c0-1.1.9-2 2-2ZM5 14v5h6v-5zm14 0h-6v5h6zm0-7h-6v5h6zM5 12h6V7H5Z"/></svg>',
    "table-delete-table": '<svg width="24" height="24"><path d="M5 21a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14c0 1.1-.9 2-2 2zm0-2h14V5H5v14z"/><path d="m13.711 15.423-1.71-1.712-1.712 1.712c-1.14 1.14-2.852-.57-1.71-1.712l1.71-1.71-1.71-1.712c-1.143-1.142.568-2.853 1.71-1.71L12 10.288l1.711-1.71c1.141-1.142 2.852.57 1.712 1.71L13.71 12l1.626 1.626c1.345 1.345-.76 2.663-1.626 1.797z" style="fill-rule:nonzero;stroke-width:1.20992"/></svg>'
};

function hu(n) {
    for (let [t, e] of Object.entries(Yf)) n.ui.registry.addIcon(t, e)
}

function Jf(n) {
    n.serializer.addNodeFilter("br", t => {
        for (let e of t)
            if (e.parent && e.parent.name === "code") {
                let i = window.tinymce.html.Node.create("#text");
                i.value = `
`, e.replace(i)
            }
    })
}

function Qf(n) {
    n.parser.addNodeFilter("div", t => {
        for (let e of t) {
            let i = e.attr("id") || "",
                r = e.attr("class") || "";
            (i === "pointer" || r.includes("pointer")) && e.remove()
        }
    })
}

function du(n) {
    Jf(n), Qf(n)
}

function pu(n) {
    return n.tagName.toLowerCase() === "code-block"
}

function mu(n, t, e, i) {
    let r = window.$components.first("code-editor"),
        o = n.selection.getBookmark();
    r.open(t, e, (s, a) => {
        i(s, a), n.focus(), n.selection.moveToBookmark(o)
    }, () => {
        n.focus(), n.selection.moveToBookmark(o)
    })
}

function fu(n, t) {
    mu(n, t.getContent(), t.getLanguage(), (e, i) => {
        t.setContent(e, i)
    })
}

function tm(n) {
    let t = n.getDoc(),
        e = t.defaultView;
    class i extends e.HTMLElement {
        constructor() {
            super();
            at(this, "editor", null);
            this.attachShadow({
                mode: "open"
            });
            let s = document.head.querySelectorAll('link[rel="stylesheet"]:not([media="print"]),style'),
                a = Array.from(s).map(c => c.cloneNode(!0)),
                l = document.createElement("div");
            l.style.pointerEvents = "none", l.contentEditable = "false", l.classList.add("CodeMirrorContainer"), l.classList.toggle("dark-mode", document.documentElement.classList.contains("dark-mode")), this.shadowRoot.append(...a, l)
        }
        getLanguage() {
            let s = c => (c.split(" ").filter(h => h.startsWith("language-"))[0] || "").replace("language-", ""),
                a = this.querySelector("code"),
                l = this.querySelector("pre");
            return s(l.className) || a && s(a.className) || ""
        }
        setContent(s, a) {
            this.editor && (this.editor.setContent(s), this.editor.setMode(a, s));
            let l = this.querySelector("pre");
            l || (l = t.createElement("pre"), this.append(l)), l.innerHTML = "";
            let c = t.createElement("code");
            l.append(c), c.innerText = s, c.className = `language-${a}`
        }
        getContent() {
            let s = this.querySelector("code") || this.querySelector("pre"),
                a = document.createElement("pre");
            a.innerHTML = s.innerHTML.replace(/\ufeff/g, "");
            let l = a.querySelectorAll("br");
            for (let c of l) c.replaceWith(`
`);
            return a.textContent
        }
        connectedCallback() {
            let s = Date.now();
            if (this.editor) return;
            this.cleanChildContent();
            let a = this.getContent(),
                c = a.split(`
`).length * 19.2 + 18 + 24;
            this.style.height = `${c}px`;
            let u = this.shadowRoot.querySelector(".CodeMirrorContainer"),
                h = d => {
                    this.editor = d.wysiwygView(u, this.shadowRoot, a, this.getLanguage()), setTimeout(() => {
                        this.style.height = null
                    }, 12)
                };
            window.importVersioned("code").then(d => {
                let f = Date.now() - s < 20 ? 20 : 0;
                setTimeout(() => h(d), f)
            })
        }
        cleanChildContent() {
            let s = this.querySelector("pre");
            if (s)
                for (let a of s.childNodes) a.nodeName === "#text" && a.textContent === "\uFEFF" && a.remove()
        }
    }
    e.customElements.define("code-block", i)
}

function em(n) {
    n.ui.registry.addIcon("codeblock", '<svg width="24" height="24"><path d="M4 3h16c.6 0 1 .4 1 1v16c0 .6-.4 1-1 1H4a1 1 0 0 1-1-1V4c0-.6.4-1 1-1Zm1 2v14h14V5Z"/><path d="M11.103 15.423c.277.277.277.738 0 .922a.692.692 0 0 1-1.106 0l-4.057-3.78a.738.738 0 0 1 0-1.107l4.057-3.872c.276-.277.83-.277 1.106 0a.724.724 0 0 1 0 1.014L7.6 12.012ZM12.897 8.577c-.245-.312-.2-.675.08-.955.28-.281.727-.27 1.027.033l4.057 3.78a.738.738 0 0 1 0 1.107l-4.057 3.872c-.277.277-.83.277-1.107 0a.724.724 0 0 1 0-1.014l3.504-3.412z"/></svg>'), n.ui.registry.addButton("codeeditor", {
        tooltip: "Insert code block",
        icon: "codeblock",
        onAction() {
            n.execCommand("codeeditor")
        }
    }), n.ui.registry.addButton("editcodeeditor", {
        tooltip: "Edit code block",
        icon: "edit-block",
        onAction() {
            n.execCommand("codeeditor")
        }
    }), n.addCommand("codeeditor", () => {
        let t = n.selection.getNode(),
            e = t.ownerDocument;
        if (pu(t)) fu(n, t);
        else {
            let i = n.selection.getContent({
                format: "text"
            });
            mu(n, i, "", (r, o) => {
                let s = e.createElement("pre"),
                    a = e.createElement("code");
                a.classList.add(`language-${o}`), a.innerText = r, s.append(a), n.insertContent(s.outerHTML)
            })
        }
    }), n.on("dblclick", () => {
        let t = n.selection.getNode();
        pu(t) && fu(n, t)
    }), n.on("PreInit", () => {
        n.parser.addNodeFilter("pre", t => {
            for (let e of t) {
                let i = window.tinymce.html.Node.create("code-block", {
                        contenteditable: "false"
                    }),
                    r = e.getAll("span");
                for (let o of r) o.unwrap();
                e.attr("style", null), e.wrap(i)
            }
        }), n.parser.addNodeFilter("code-block", t => {
            for (let e of t) e.attr("contenteditable", "false")
        }), n.serializer.addNodeFilter("code-block", t => {
            for (let e of t) e.unwrap()
        })
    }), n.ui.registry.addContextToolbar("codeeditor", {
        predicate(t) {
            return t.nodeName.toLowerCase() === "code-block"
        },
        items: "editcodeeditor",
        position: "node",
        scope: "node"
    }), n.on("PreInit", () => {
        tm(n)
    })
}

function gu() {
    return em
}
var pt = null,
    oe = null,
    re = {};

function zo(n) {
    return n.hasAttribute("drawio-diagram")
}

function nm(n, t = null) {
    pt = n, oe = t, window.$components.first("image-manager").show(i => {
        if (t) {
            let r = t.querySelector("img");
            pt.undoManager.transact(() => {
                pt.dom.setAttrib(r, "src", i.url), pt.dom.setAttrib(t, "drawio-diagram", i.id)
            })
        } else {
            let r = `<div drawio-diagram="${i.id}" contenteditable="false"><img src="${i.url}"></div>`;
            pt.insertContent(r)
        }
    }, "drawio")
}
async function im(n) {
    let t = window.baseUrl("/loading.gif"),
        e = o => {
            o.status === 413 ? window.$events.emit("error", re.translations.serverUploadLimitText) : window.$events.emit("error", re.translations.imageUploadErrorText), console.error(o)
        };
    if (oe) {
        ee();
        let o = oe.querySelector("img");
        try {
            let s = await Po(n, re.pageId);
            pt.undoManager.transact(() => {
                pt.dom.setAttrib(o, "src", s.url), pt.dom.setAttrib(oe, "drawio-diagram", s.id)
            })
        } catch (s) {
            throw e(s), new Error(`Failed to save image with error: ${s}`)
        }
        return
    }
    await ns(5);
    let i = `drawing-${Math.random().toString(16).slice(2)}`,
        r = `drawing-wrap-${Math.random().toString(16).slice(2)}`;
    pt.insertContent(`<div drawio-diagram contenteditable="false" id="${r}"><img src="${t}" id="${i}"></div>`), ee();
    try {
        let o = await Po(n, re.pageId);
        pt.undoManager.transact(() => {
            pt.dom.setAttrib(i, "src", o.url), pt.dom.setAttrib(r, "drawio-diagram", o.id)
        })
    } catch (o) {
        throw pt.dom.remove(r), e(o), new Error(`Failed to save image with error: ${o}`)
    }
}

function rm() {
    if (!oe) return Promise.resolve("");
    let n = oe.getAttribute("drawio-diagram");
    return _i(n)
}

function bu(n, t = null) {
    pt = n, oe = t, tn(re.drawioUrl, rm, im)
}

function om(n) {
    n.addCommand("drawio", () => {
        let t = n.selection.getNode();
        bu(n, zo(t) ? t : null)
    }), n.ui.registry.addIcon("diagram", `<svg width="24" height="24" fill="${re.darkMode?"#BBB":"#000000"}" xmlns="http://www.w3.org/2000/svg"><path d="M20.716 7.639V2.845h-4.794v1.598h-7.99V2.845H3.138v4.794h1.598v7.99H3.138v4.794h4.794v-1.598h7.99v1.598h4.794v-4.794h-1.598v-7.99zM4.736 4.443h1.598V6.04H4.736zm1.598 14.382H4.736v-1.598h1.598zm9.588-1.598h-7.99v-1.598H6.334v-7.99h1.598V6.04h7.99v1.598h1.598v7.99h-1.598zm3.196 1.598H17.52v-1.598h1.598zM17.52 6.04V4.443h1.598V6.04zm-4.21 7.19h-2.79l-.582 1.599H8.643l2.717-7.191h1.119l2.724 7.19h-1.302zm-2.43-1.006h2.086l-1.039-3.06z"/></svg>`), n.ui.registry.addSplitButton("drawio", {
        tooltip: "Insert/edit drawing",
        icon: "diagram",
        onAction() {
            n.execCommand("drawio"), window.document.body.dispatchEvent(new Event("mousedown", {
                bubbles: !0
            }))
        },
        fetch(t) {
            t([{
                type: "choiceitem",
                text: "Drawing manager",
                value: "drawing-manager"
            }])
        },
        onItemAction(t, e) {
            if (e === "drawing-manager") {
                let i = n.selection.getNode();
                nm(n, zo(i) ? i : null)
            }
        }
    }), n.on("dblclick", () => {
        let t = n.selection.getNode();
        zo(t) && bu(n, t)
    }), n.on("SetContent", () => {
        let t = n.dom.select("body > div[drawio-diagram]");
        t.length && n.undoManager.transact(() => {
            for (let e of t) e.setAttribute("contenteditable", "false")
        })
    })
}

function vu(n) {
    return re = n, om
}

function sm(n) {
    n.addCommand("InsertHorizontalRule", () => {
        let t = document.createElement("hr"),
            e = n.selection.getNode(),
            {
                parentNode: i
            } = e;
        i.insertBefore(t, e)
    }), n.ui.registry.addButton("customhr", {
        icon: "horizontal-rule",
        tooltip: "Insert horizontal line",
        onAction() {
            n.execCommand("InsertHorizontalRule")
        }
    })
}

function wu() {
    return sm
}

function am(n) {
    n.ui.registry.addButton("imagemanager-insert", {
        title: "Insert image",
        icon: "image",
        tooltip: "Insert image",
        onAction() {
            window.$components.first("image-manager").show(e => {
                let i = e.thumbs?.display || e.url,
                    r = `<a href="${e.url}" target="_blank">`;
                r += `<img src="${i}" alt="${e.name}">`, r += "</a>", n.execCommand("mceInsertContent", !1, r)
            }, "gallery")
        }
    })
}

function yu() {
    return am
}

function lm(n) {
    let t = {
        title: "About the WYSIWYG Editor",
        url: window.baseUrl("/help/wysiwyg")
    };
    n.ui.registry.addButton("about", {
        icon: "help",
        tooltip: "About the editor",
        onAction() {
            window.tinymce.activeEditor.windowManager.openUrl(t)
        }
    })
}

function xu() {
    return lm
}
var ku = ["p", "h1", "h2", "h3", "h4", "h5", "h6", "div", "blockquote", "pre", "code-block", "details", "ul", "ol", "table", "hr"];

function lr(n) {
    return n.selection.getNode().closest("details")
}

function cm(n, t) {
    let e = lr(n);
    e && n.undoManager.transact(() => {
        let i = e.querySelector("summary");
        i || (i = document.createElement("summary"), e.prepend(i)), i.textContent = t
    })
}

function um(n) {
    return {
        title: "Edit collapsible block",
        body: {
            type: "panel",
            items: [{
                type: "input",
                name: "summary",
                label: "Toggle label"
            }]
        },
        buttons: [{
            type: "cancel",
            text: "Cancel"
        }, {
            type: "submit",
            text: "Save",
            primary: !0
        }],
        onSubmit(t) {
            let {
                summary: e
            } = t.getData();
            cm(n, e), t.close()
        }
    }
}

function hm(n) {
    let t = n.querySelector("summary");
    return t ? t.textContent : ""
}

function Cu(n) {
    let t = lr(n);
    n.windowManager.open(um(n)).setData({
        summary: hm(t)
    })
}

function dm(n) {
    let t = n.selection.getNode().closest("details"),
        e = n.selection.getBookmark();
    if (t) {
        let i = t.querySelectorAll("details > *:not(summary, doc-root), doc-root > *");
        n.undoManager.transact(() => {
            for (let r of i) t.parentNode.insertBefore(r, t);
            t.remove()
        })
    }
    n.focus(), n.selection.moveToBookmark(e)
}

function Ho(n) {
    n.attr("contenteditable", null);
    let t = !1;
    for (let e of n.children()) e.name === "doc-root" && (e.unwrap(), t = !0);
    t && Ho(n)
}

function pm(n) {
    Ho(n), n.attr("contenteditable", "false");
    let t = window.tinymce.html.Node.create("doc-root", {
            contenteditable: "true"
        }),
        e = null;
    for (let i of n.children()) {
        if (i.name === "summary") continue;
        ku.includes(i.name) ? (t.append(i), e = null) : (e || (e = window.tinymce.html.Node.create("p"), t.append(e)), e.append(i))
    }
    n.append(t)
}

function fm(n) {
    n.parser.addNodeFilter("details", t => {
        for (let e of t) pm(e)
    }), n.serializer.addNodeFilter("details", t => {
        for (let e of t) Ho(e), e.attr("open", null)
    }), n.serializer.addNodeFilter("doc-root", t => {
        for (let e of t) e.unwrap()
    })
}

function mm(n) {
    n.ui.registry.addIcon("details", '<svg width="24" height="24"><path d="M8.2 9a.5.5 0 0 0-.4.8l4 5.6a.5.5 0 0 0 .8 0l4-5.6a.5.5 0 0 0-.4-.8ZM20.122 18.151h-16c-.964 0-.934 2.7 0 2.7h16c1.139 0 1.173-2.7 0-2.7zM20.122 3.042h-16c-.964 0-.934 2.7 0 2.7h16c1.139 0 1.173-2.7 0-2.7z"/></svg>'), n.ui.registry.addIcon("togglefold", '<svg height="24"  width="24"><path d="M8.12 19.3c.39.39 1.02.39 1.41 0L12 16.83l2.47 2.47c.39.39 1.02.39 1.41 0 .39-.39.39-1.02 0-1.41l-3.17-3.17c-.39-.39-1.02-.39-1.41 0l-3.17 3.17c-.4.38-.4 1.02-.01 1.41zm7.76-14.6c-.39-.39-1.02-.39-1.41 0L12 7.17 9.53 4.7c-.39-.39-1.02-.39-1.41 0-.39.39-.39 1.03 0 1.42l3.17 3.17c.39.39 1.02.39 1.41 0l3.17-3.17c.4-.39.4-1.03.01-1.42z"/></svg>'), n.ui.registry.addIcon("togglelabel", '<svg height="18" width="18" viewBox="0 0 24 24"><path d="M21.41,11.41l-8.83-8.83C12.21,2.21,11.7,2,11.17,2H4C2.9,2,2,2.9,2,4v7.17c0,0.53,0.21,1.04,0.59,1.41l8.83,8.83 c0.78,0.78,2.05,0.78,2.83,0l7.17-7.17C22.2,13.46,22.2,12.2,21.41,11.41z M6.5,8C5.67,8,5,7.33,5,6.5S5.67,5,6.5,5S8,5.67,8,6.5 S7.33,8,6.5,8z"/></svg>'), n.ui.registry.addButton("details", {
        icon: "details",
        tooltip: "Insert collapsible block",
        onAction() {
            n.execCommand("InsertDetailsBlock")
        }
    }), n.ui.registry.addButton("removedetails", {
        icon: "table-delete-table",
        tooltip: "Unwrap",
        onAction() {
            dm(n)
        }
    }), n.ui.registry.addButton("editdetials", {
        icon: "togglelabel",
        tooltip: "Edit label",
        onAction() {
            Cu(n)
        }
    }), n.on("dblclick", t => {
        !lr(n) || t.target.closest("doc-root") || Cu(n)
    }), n.ui.registry.addButton("toggledetails", {
        icon: "togglefold",
        tooltip: "Toggle open/closed",
        onAction() {
            lr(n).toggleAttribute("open"), n.focus()
        }
    }), n.addCommand("InsertDetailsBlock", () => {
        let t = n.selection.getContent({
                format: "html"
            }),
            e = document.createElement("details"),
            i = document.createElement("summary"),
            r = `details-${Date.now()}`;
        e.setAttribute("data-id", r), e.appendChild(i), t || (t = "<p><br></p>"), e.innerHTML += t, n.insertContent(e.outerHTML), n.focus();
        let o = n.dom.select(`[data-id="${r}"]`)[0] || null;
        if (o) {
            let s = o.querySelector("doc-root > *");
            s && s.focus(), o.removeAttribute("data-id")
        }
    }), n.ui.registry.addContextToolbar("details", {
        predicate(t) {
            return t.nodeName.toLowerCase() === "details"
        },
        items: "editdetials toggledetails removedetails",
        position: "node",
        scope: "node"
    }), n.on("PreInit", () => {
        fm(n)
    })
}

function Eu() {
    return mm
}

function gm(n) {
    let t = n.closest("li");
    return t && t.parentNode.nodeName === "UL" && t.classList.contains("task-list-item")
}

function bm(n, t, e) {
    let i = t.getBoundingClientRect();
    n.clientX <= i.right && n.clientX >= i.left && n.clientY >= i.top && n.clientY <= i.bottom || e.undoManager.transact(() => {
        t.hasAttribute("checked") ? t.removeAttribute("checked") : t.setAttribute("checked", "checked")
    })
}

function vm(n) {
    n.attr("class", "task-list-item");
    for (let t of n.children()) t.name === "input" && (t.attr("checked") === "checked" && n.attr("checked", "checked"), t.remove())
}

function wm(n) {
    let t = n.attr("checked") === "checked";
    n.attr("checked", null);
    let e = {
        type: "checkbox",
        disabled: "disabled"
    };
    t && (e.checked = "checked");
    let i = window.tinymce.html.Node.create("input", e);
    i.shortEnded = !0, n.firstChild ? n.insert(i, n.firstChild, !0) : n.append(i)
}

function ym(n) {
    n.ui.registry.addIcon("tasklist", '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M22,8c0-0.55-0.45-1-1-1h-7c-0.55,0-1,0.45-1,1s0.45,1,1,1h7C21.55,9,22,8.55,22,8z M13,16c0,0.55,0.45,1,1,1h7 c0.55,0,1-0.45,1-1c0-0.55-0.45-1-1-1h-7C13.45,15,13,15.45,13,16z M10.47,4.63c0.39,0.39,0.39,1.02,0,1.41l-4.23,4.25 c-0.39,0.39-1.02,0.39-1.42,0L2.7,8.16c-0.39-0.39-0.39-1.02,0-1.41c0.39-0.39,1.02-0.39,1.41,0l1.42,1.42l3.54-3.54 C9.45,4.25,10.09,4.25,10.47,4.63z M10.48,12.64c0.39,0.39,0.39,1.02,0,1.41l-4.23,4.25c-0.39,0.39-1.02,0.39-1.42,0L2.7,16.16 c-0.39-0.39-0.39-1.02,0-1.41s1.02-0.39,1.41,0l1.42,1.42l3.54-3.54C9.45,12.25,10.09,12.25,10.48,12.64L10.48,12.64z"/></svg>'), n.ui.registry.addToggleButton("tasklist", {
        tooltip: "Task list",
        icon: "tasklist",
        active: !1,
        onAction(i) {
            i.isActive() ? n.execCommand("RemoveList") : n.execCommand("InsertUnorderedList", null, {
                "list-item-attributes": {
                    class: "task-list-item"
                },
                "list-style-type": "tasklist"
            })
        },
        onSetup(i) {
            n.on("NodeChange", r => {
                let o = r.parents.find(a => a.nodeName === "LI"),
                    s = o && o.classList.contains("task-list-item");
                i.setActive(!!s)
            })
        }
    });
    let t = n.ui.registry.getAll().buttons.bullist;
    t.onSetup = function(r) {
        n.on("NodeChange", o => {
            let s = o.parents.find(c => c.nodeName === "LI"),
                a = s && s.classList.contains("task-list-item"),
                l = s && s.parentNode.nodeName === "UL";
            r.setActive(!!(l && !a))
        })
    }, t.onAction = function() {
        gm(n.selection.getNode()) && n.execCommand("InsertOrderedList", null, {
            "list-item-attributes": {
                class: null
            }
        }), n.execCommand("InsertUnorderedList", null, {
            "list-item-attributes": {
                class: null
            }
        })
    };
    let e = n.ui.registry.getAll().buttons.numlist;
    e.onAction = function() {
        n.execCommand("InsertOrderedList", null, {
            "list-item-attributes": {
                class: null
            }
        })
    }, n.on("PreInit", () => {
        n.parser.addNodeFilter("li", i => {
            for (let r of i) r.attributes.map.class === "task-list-item" && vm(r)
        }), n.serializer.addNodeFilter("li", i => {
            for (let r of i) r.attributes.map.class === "task-list-item" && wm(r)
        })
    }), n.on("click", i => {
        let r = i.target;
        r.nodeName === "LI" && r.classList.contains("task-list-item") && (bm(i, r, n), i.preventDefault())
    })
}

function _u() {
    return ym
}
var xm = [{
        title: "Large Header",
        format: "h2",
        preview: "color: blue;"
    }, {
        title: "Medium Header",
        format: "h3"
    }, {
        title: "Small Header",
        format: "h4"
    }, {
        title: "Tiny Header",
        format: "h5"
    }, {
        title: "Paragraph",
        format: "p",
        exact: !0,
        classes: ""
    }, {
        title: "Blockquote",
        format: "blockquote"
    }, {
        title: "Callouts",
        items: [{
            title: "Information",
            format: "calloutinfo"
        }, {
            title: "Success",
            format: "calloutsuccess"
        }, {
            title: "Warning",
            format: "calloutwarning"
        }, {
            title: "Danger",
            format: "calloutdanger"
        }]
    }],
    km = {
        alignleft: {
            selector: "p,h1,h2,h3,h4,h5,h6,td,th,div,ul,ol,li,table,img",
            classes: "align-left"
        },
        aligncenter: {
            selector: "p,h1,h2,h3,h4,h5,h6,td,th,div,ul,ol,li,table,img",
            classes: "align-center"
        },
        alignright: {
            selector: "p,h1,h2,h3,h4,h5,h6,td,th,div,ul,ol,li,table,img",
            classes: "align-right"
        },
        calloutsuccess: {
            block: "p",
            exact: !0,
            attributes: {
                class: "callout success"
            }
        },
        calloutinfo: {
            block: "p",
            exact: !0,
            attributes: {
                class: "callout info"
            }
        },
        calloutwarning: {
            block: "p",
            exact: !0,
            attributes: {
                class: "callout warning"
            }
        },
        calloutdanger: {
            block: "p",
            exact: !0,
            attributes: {
                class: "callout danger"
            }
        }
    },
    Cm = ["#BFEDD2", "", "#FBEEB8", "", "#F8CAC6", "", "#ECCAFA", "", "#C2E0F4", "", "#2DC26B", "", "#F1C40F", "", "#E03E2D", "", "#B96AD9", "", "#3598DB", "", "#169179", "", "#E67E23", "", "#BA372A", "", "#843FA1", "", "#236FA1", "", "#ECF0F1", "", "#CED4D9", "", "#95A5A6", "", "#7E8C8D", "", "#34495E", "", "#000000", "", "#ffffff", ""];

function Em(n, t, e) {
    if (e.filetype === "file") {
        let i = window.$components.first("entity-selector-popup"),
            r = this.selection.getContent({
                format: "text"
            }).trim();
        i.show(o => {
            n(o.link, {
                text: o.name,
                title: o.name
            })
        }, r)
    }
    e.filetype === "image" && window.$components.first("image-manager").show(r => {
        n(r.url, {
            alt: r.name
        })
    }, "gallery")
}

function _m(n) {
    let t = ["image", "table", "link", "autolink", "fullscreen", "code", "customhr", "autosave", "lists", "codeeditor", "media", "imagemanager", "about", "details", "tasklist", n.textDirection === "rtl" ? "directionality" : ""];
    return window.tinymce.PluginManager.add("codeeditor", gu()), window.tinymce.PluginManager.add("customhr", wu()), window.tinymce.PluginManager.add("imagemanager", yu()), window.tinymce.PluginManager.add("about", xu()), window.tinymce.PluginManager.add("details", Eu()), window.tinymce.PluginManager.add("tasklist", _u()), n.drawioUrl && (window.tinymce.PluginManager.add("drawio", vu(n)), t.push("drawio")), t.filter(e => !!e)
}

function Sm() {
    let n = document.head.innerHTML.split(`
`),
        t = n.findIndex(i => i.trim() === "<!-- Start: custom user content -->"),
        e = n.findIndex(i => i.trim() === "<!-- End: custom user content -->");
    return t === -1 || e === -1 ? "" : n.slice(t + 1, e).join(`
`)
}

function Am(n) {
    return function(e) {
        function i() {
            n.darkMode && e.contentDocument.documentElement.classList.add("dark-mode"), window.$events.emit("editor-html-change", "")
        }
        e.on("ExecCommand change input NodeChange ObjectResized", i), ou(e), lu(e, n), e.on("init", () => {
            i(), su(e), window.editor = e, ru(e)
        }), e.on("PreInit", () => {
            du(e)
        }), window.$events.emitPublic(n.containerElement, "editor-tinymce::setup", {
            editor: e
        }), e.ui.registry.addButton("inlinecode", {
            tooltip: "Inline code",
            icon: "sourcecode",
            onAction() {
                e.execCommand("mceToggleFormat", !1, "code")
            }
        })
    }
}

function Dm(n) {
    return `
html, body, html.dark-mode {
    background: ${n.darkMode?"#222":"#fff"};
} 
body {
    padding-left: 15px !important;
    padding-right: 15px !important; 
    height: initial !important;
    margin:0!important; 
    margin-left: auto! important;
    margin-right: auto !important;
    overflow-y: hidden !important;
}`.trim().replace(`
`, "")
}

function Su(n) {
    return window.tinymce.addI18n(n.language, n.translationMap), {
        width: "100%",
        height: "100%",
        selector: "#html-editor",
        cache_suffix: `?version=${document.querySelector('script[src*="/dist/app.js"]').getAttribute("src").split("?version=")[1]}`,
        content_css: [window.baseUrl("/dist/styles.css")],
        branding: !1,
        skin: n.darkMode ? "tinymce-5-dark" : "tinymce-5",
        body_class: "page-content",
        browser_spellcheck: !0,
        relative_urls: !1,
        language: n.language,
        directionality: n.textDirection,
        remove_script_host: !1,
        document_base_url: window.baseUrl("/"),
        end_container_on_empty_block: !0,
        remove_trailing_brs: !1,
        statusbar: !1,
        menubar: !1,
        paste_data_images: !1,
        extended_valid_elements: "pre[*],svg[*],div[drawio-diagram],details[*],summary[*],div[*],li[class|checked|style]",
        automatic_uploads: !1,
        custom_elements: "doc-root,code-block",
        valid_children: ["-div[p|h1|h2|h3|h4|h5|h6|blockquote|code-block]", "+div[pre|img]", "-doc-root[doc-root|#text]", "-li[details]", "+code-block[pre]", "+doc-root[p|h1|h2|h3|h4|h5|h6|blockquote|code-block|div|hr]"].join(","),
        plugins: _m(n),
        contextmenu: !1,
        toolbar: cu(n),
        content_style: Dm(n),
        style_formats: xm,
        style_formats_merge: !1,
        media_alt_source: !1,
        media_poster: !1,
        formats: km,
        table_style_by_css: !0,
        table_use_colgroups: !0,
        file_picker_types: "file image",
        color_map: Cm,
        file_picker_callback: Em,
        paste_preprocess(e, i) {
            let {
                content: r
            } = i;
            r.indexOf('<img src="file://') !== -1 && (i.content = "")
        },
        init_instance_callback(e) {
            let i = e.getDoc().querySelector("head");
            i.innerHTML += Sm()
        },
        setup(e) {
            hu(e), uu(e), Am(n)(e)
        }
    }
}
var cr = class extends g {
    setup() {
        this.elem = this.$el, this.pageId = this.$opts.pageId, this.textDirection = this.$opts.textDirection, this.isDarkMode = document.documentElement.classList.contains("dark-mode"), this.tinyMceConfig = Su({
            language: this.$opts.language,
            containerElement: this.elem,
            darkMode: this.isDarkMode,
            textDirection: this.textDirection,
            drawioUrl: this.getDrawIoUrl(),
            pageId: Number(this.pageId),
            translations: {
                imageUploadErrorText: this.$opts.imageUploadErrorText,
                serverUploadLimitText: this.$opts.serverUploadLimitText
            },
            translationMap: window.editor_translations
        }), window.$events.emitPublic(this.elem, "editor-tinymce::pre-init", {
            config: this.tinyMceConfig
        }), window.tinymce.init(this.tinyMceConfig).then(t => {
            this.editor = t[0]
        })
    }
    getDrawIoUrl() {
        let t = document.querySelector("[drawio-url]");
        return t ? t.getAttribute("drawio-url") : ""
    }
    getContent() {
        return {
            html: this.editor.getContent()
        }
    }
};
window.baseUrl = function(t) {
    let e = t,
        i = document.querySelector('meta[name="base-url"]').getAttribute("content");
    return i[i.length - 1] === "/" && (i = i.slice(0, i.length - 1)), e[0] === "/" && (e = e.slice(1)), `${i}/${e}`
};
window.importVersioned = function(t) {
    let e = document.querySelector('link[href*="/dist/styles.css?version="]').href.split("?version=").pop();
    return import(window.baseUrl(`dist/${t}.js?version=${e}`))
};
window.$http = pr;
window.$events = dr;
var Ee = new Ko;
window.trans = Ee.get.bind(Ee);
window.trans_choice = Ee.getPlural.bind(Ee);
window.trans_plural = Ee.parsePlural.bind(Ee);
vr(Uo);
window.$components = wr;
br();
/*! Bundled license information:

sortablejs/modular/sortable.esm.js:
  (**!
   * Sortable 1.15.0
   * @author	RubaXa   <trash@rubaxa.org>
   * @author	owenm    <owen23355@gmail.com>
   * @license MIT
   *)
*/
//# sourceMappingURL=app.js.map
