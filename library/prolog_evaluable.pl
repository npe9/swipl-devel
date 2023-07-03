/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        jan@swi-prolog.org
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2023, SWI-Prolog Solutions b.v.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

:- module(prolog_evaluable,
          [ evaluable_property/2
          ]).

/** <module> Inspect properties of evaluable functions
*/

%!  evaluable_property(?Function, ?Property) is nondet.
%
%   True when Property is a property of the evaluable function Function.
%   _Evaluable functions_ are expressions processed   by  the arithmetic
%   predicates is/2, </2, =</2, =:=/2, >/2  and >=/2. Defined properties
%   are:
%
%     - built_in
%       Function is built-in. The proposal defines additional properties
%       for systems that allow defining new functions at runtime.
%       SWI-Prolog provides library(arithmetic) for this, which rewrites
%       the source as interleaved predicate calls and built-in function
%       evaluation.
%     - template(Function, Return)
%       Type support.  Types used are `integer`, `rational` and `float`.
%       Functions that copy the type to the output use a variable to
%       indicate this, e.g., template(-Type, Type).  A function may
%       have multiple type templates.
%
%   Future versions may provide this predicate as a built-in.
%
%   @compat discussed by several implementors, initiated by Paulo Moura.

evaluable_property(Templ, Prop), ground(Prop) =>
    evaluable_property_(Templ, Prop), !.
evaluable_property(Templ, Prop) =>
    evaluable_property_(Templ, Prop).

evaluable_property_(Templ, built_in) :-
    current_arithmetic_function(Templ).
evaluable_property_(Templ, template(Templ, Ret)) :-
    eval_type(Templ, Ret).

eval_type(float*_,float).
eval_type(_*float,float).
eval_type(rational*rational,rational).
eval_type(float**_,float).
eval_type(_**float,float).
eval_type(rational**rational,rational).
eval_type(rational**rational,float).
eval_type(+Type,Type).
eval_type(float+_,float).
eval_type(_+float,float).
eval_type(rational+rational,rational).
eval_type(-Type,Type).
eval_type(float-_,float).
eval_type(_-float,float).
eval_type(rational-rational,rational).
eval_type(float/_,float).
eval_type(_/float,float).
eval_type(rational/rational,rational).
eval_type(rational/rational,float).
eval_type(_//_,integer).
eval_type(integer/\integer,integer).
eval_type(integer<<integer,integer).
eval_type(integer>>integer,integer).
eval_type(\integer,integer).
eval_type(integer\/integer,integer).
eval_type(float^_,float).
eval_type(_^float,float).
eval_type(rational^rational,rational).
eval_type(rational^rational,float).
eval_type(abs(Type),Type).
eval_type(acos(_),float).
eval_type(acosh(_),float).
eval_type(asin(_),float).
eval_type(asinh(_),float_).
eval_type(atan(_),float).
eval_type(atan(_,_),float).
eval_type(atan2(_,_),float).
eval_type(atanh(_),float).
eval_type(ceil(_),integer).
eval_type(ceiling(_),integer).
eval_type(cmpr(_,_),integer).
eval_type(copysign(Type,_),Type).
eval_type(cos(_),float).
eval_type(cosh(_),float).
eval_type(cputime,float).
eval_type(denominator(rational),integer).
eval_type(_ div _,integer).
eval_type(e,float).
eval_type(epsilon,float).
eval_type(erf(_),float).
eval_type(erfc(_),float).
eval_type(eval(Type),Type).
eval_type(exp(_),float).
eval_type(float(_),float).
eval_type(float_fractional_part(Type),Type).
eval_type(float_integer_part(Type),Type).
eval_type(floor(_),integer).
eval_type(gcd(integer,integer),integer).
eval_type(getbit(integer,integer),integer).
eval_type(inf,float).
eval_type(integer(_),integer).
eval_type(lcm(integer,integer),integer).
eval_type(lgamma(_),float).
eval_type(log(_),float).
eval_type(log10(_),float).
eval_type(lsb(integer),integer).
eval_type(max(Type,_),Type).
eval_type(max(_,Type),Type).
eval_type(maxr(Type,_),Type).
eval_type(maxr(_,Type),Type).
eval_type(min(Type,_),Type).
eval_type(min(_,Type),Type).
eval_type(minr(Type,_),Type).
eval_type(minr(_,Type),Type).
eval_type(integer mod integer,integer).
eval_type(msb(integer),integer).
eval_type(nan,float).
eval_type(nexttoward(_,_),float).
eval_type(numerator(rational),integer).
eval_type(pi,float).
eval_type(popcount(integer),integer).
eval_type(powm(integer,integer,integer),integer).
eval_type(random(integer),integer).
eval_type(random_float,float).
eval_type(rational(_),rational).
eval_type(rationalize(_),rational).
eval_type(rational rdiv rational,rational).
eval_type(integer rem integer,integer).
eval_type(round(_),integer).
eval_type(roundtoward(_,_),float).
eval_type(sign(_),integer).
eval_type(sin(_),float).
eval_type(sinh(_),float).
eval_type(sqrt(_),float).
eval_type(tan(_),float).
eval_type(tanh(_),float).
eval_type(truncate(_),integer).
eval_type(integer xor integer,integer_).
