#include "interstellar_math.hpp"
#include <cmath>

// For some reason I wanted these in C...
// You can just remake these in lua if you want.
namespace INTERSTELLAR_NAMESPACE::Math {
    using namespace API;

    namespace Roots {
        constexpr double err = 1.0E-10;
        constexpr double _1_3 = 1.0 / 3.0;
        constexpr double _sqrt_3 = 1.7320508076;

        // ax + b
        inline double linear(double a, double b)
        {
            return -b / a;
        }

        static int llinear(lua_State* L)
        {
            double a = luaL::checknumber(L, 1);
            double b = luaL::checknumber(L, 2);
            lua::pushnumber(L, linear(a, b));
            return 1;
        }

        // ax^2 + bx + c
        inline void quadric(double a, double b, double c, double& x1, double& x2)
        {
            double k = -b / (2 * a);
            double u2 = k * k - c / a;
            if (u2 > -err && u2 < err) {
                x1 = 0, x2 = 0;
            }
            double u = pow(u2, 0.5);
            x1 = k - u, x2 = k + u;
        }

        static int lquadric(lua_State* L)
        {
            double a = luaL::checknumber(L, 1);
            double b = luaL::checknumber(L, 2);
            double c = luaL::checknumber(L, 3);
            double x1, x2;
            quadric(a, b, c, x1, x2);
            lua::pushnumber(L, x1);
            lua::pushnumber(L, x2);
            return 2;
        }

        // ax^3 + bx^2 + cx + d
        inline void cubic(double a, double b, double c, double d, double& x1, double& x2, double& x3)
        {
            double k = -b / (3 * a);
            double p = (3 * a * c - b * b) / (9 * a * a);
            double q = (2 * b * b * b - 9 * a * b * c + 27 * a * a * d) / (54 * a * a * a);
            double r = p * p * p + q * q;
            double s = pow(r, 0.5) + q;
            if (s > -err && s < err) {
                if (q < 0) {
                    x1 = k + pow(-2 * q, _1_3), x2 = 0, x3 = 0;
                    return;
                }
                x1 = k - pow(-2 * q, _1_3), x2 = 0, x3 = 0;
                return;
            }
            else if (r < 0) {
                double m = pow(-p, 0.5);
                double d = atan2(pow(-r, 0.5), q) / 3;
                double u = m * cos(d);
                double v = m * sin(d);
                x1 = k - 2 * u, x2 = k + u - _sqrt_3 * v, x3 = k + u + _sqrt_3 * v;
                return;
            }
            else if (s < 0) {
                double m = -pow(-s, _1_3);
                x1 = k + p / m - m, x2 = 0, x3 = 0;
                return;
            }
            double m = pow(s, _1_3);
            x1 = k + p / m - m, x2 = 0, x3 = 0;
        }

        static int lcubic(lua_State* L)
        {
            double a = luaL::checknumber(L, 1);
            double b = luaL::checknumber(L, 2);
            double c = luaL::checknumber(L, 3);
            double d = luaL::checknumber(L, 4);
            double x1, x2, x3;
            cubic(a, b, c, d, x1, x2, x3);
            lua::pushnumber(L, x1);
            lua::pushnumber(L, x2);
            lua::pushnumber(L, x3);
            return 3;
        }

        // ax^4 + bx^3 + cx^2 + dx + e
        inline void quartic(double a, double b, double c, double d, double e, double& x1, double& x2, double& x3, double& x4)
        {
            double k = -b / (4 * a);
            double p = (8 * a * c - 3 * b * b) / (8 * a * a);
            double q = (b * b * b + 8 * a * a * d - 4 * a * b * c) / (8 * a * a * a);
            double r = (16 * a * a * b * b * c + 256 * a * a * a * a * e - 3 * a * b * b * b * b - 64 * a * a * a * b * d) / (256 * a * a * a * a * a);
            double h0, h1, h2;
            cubic(1, 2 * p, p * p - 4 * r, -q * q, h0, h1, h2);
            double s = h2 > 0 ? h2 : h0;

            if (s < err) {
                double f0, f1;
                quadric(1, p, r, f0, f1);
                if (!f1 || f1 < 0) {
                    x1 = 0, x2 = 0, x3 = 0, x4 = 0;
                    return;
                }
                double f = pow(f1, 0.5);
                x1 = k - f, x2 = k + f, x3 = 0, x4 = 0;
                return;
            }

            double h = pow(s, 0.5);
            double f = (h * h * h + h * p - q) / (2 * h);
            if (f > -err && f < err) {
                x1 = k - h, x2 = k, x3 = 0, x4 = 0;
                return;
            }

            double r0, r1;
            quadric(1, h, f, r0, r1);
            double r2, r3;
            quadric(1, -h, r / f, r2, r3);

            if (r0 && r2) {
                x1 = k + r0, x2 = k + r1, x3 = k + r2, x4 = k + r3;
                return;
            }
            else if (r0) {
                x1 = k + r0, x2 = k + r1, x3 = 0, x4 = 0;
                return;
            }
            else if (r2) {
                x1 = k + r2, x2 = k + r3, x3 = 0, x4 = 0;
                return;
            }

            x1 = 0, x2 = 0, x3 = 0, x4 = 0;
        }

        static int lquartic(lua_State* L)
        {
            double a = luaL::checknumber(L, 1);
            double b = luaL::checknumber(L, 2);
            double c = luaL::checknumber(L, 3);
            double d = luaL::checknumber(L, 4);
            double e = luaL::checknumber(L, 5);
            double x1, x2, x3, x4;
            quartic(a, b, c, d, e, x1, x2, x3, x4);
            lua::pushnumber(L, x1);
            lua::pushnumber(L, x2);
            lua::pushnumber(L, x3);
            lua::pushnumber(L, x4);
            return 4;
        }
    }

    void push(lua_State* L, UMODULE hndle)
    {
        lua::pushvalue(L, indexer::global);
        lua::getfield(L, -1, "math");
        lua::remove(L, -2);

        lua::newtable(L);

        lua::pushcfunction(L, Roots::llinear);
        lua::setfield(L, -2, "linear");

        lua::pushcfunction(L, Roots::lquadric);
        lua::setfield(L, -2, "quadric");

        lua::pushcfunction(L, Roots::lcubic);
        lua::setfield(L, -2, "cubic");

        lua::pushcfunction(L, Roots::lquartic);
        lua::setfield(L, -2, "quartic");

        lua::setfield(L, -2, "roots");
    }

    void api() {
        Reflection::add("math", push);
    }
}