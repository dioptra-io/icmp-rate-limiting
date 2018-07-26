//
// Created by System Administrator on 16/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_PLOTTER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_PLOTTER_T_HPP

#include <tins/tins.h>
#include <unordered_map>

#include <EasyBMP.h>
#include "gnuplot-iostream.h"
#include "markov_t.hpp"
#include "utils/struct_utils_t.hpp"
#include "utils/container_utils_t.hpp"

class rate_limit_plotter_t {
public:

    using probing_rates_t = std::vector<int>;
    using loss_rates_t = std::vector<double>;


    using responsive_info_probe_t = std::pair<bool, Tins::Packet>;

    struct plot_infos_t{
        std::string title;
    };

    /**
     * This function plots on the Y axis the loss rates and on the X axis the corresponding probing rates.
     * @param losses
     * @param rates
     */
    void plot_loss_rate_gilbert_eliott(const std::vector<double> &losses, const std::vector<int> &rates, const std::vector<gilbert_elliot_t> & burst_models);

    /**
     * This function plots on Y axis the different transitions probabilities and on X axis the corresponding
     * rates.
     * @param probabilities
     * @param rates
     */
//    void plot_gilbert_eliot(const std::vector<gilbert_elliot_t> & probabilities, const std::vector<int> & rates);

    /**
     * Plot the raw data of an interface
     * @param packets
     */
    void plot_raw(const std::vector<responsive_info_probe_t> & packets);


    void plot_bitmap_raw(const std::unordered_map<Tins::IPv4Address, std::vector<responsive_info_probe_t>> & raw_data, const std::string & title);
    template<typename Sort>
    void plot_aggregate(const std::unordered_map<Tins::IPv4Address, utils::stats_t> & stats_by_ip, const plot_infos_t & plot_infos,  Sort sort){
        // First sort the data by Sort. X axis will be the IP, Y the values
        using stats_t = utils::stats_t;
        std::vector<stats_t> sorted_stats = utils::values(stats_by_ip);
        std::sort(sorted_stats.begin(), sorted_stats.end(), [sort](const stats_t & stat_ip1, const stats_t & stat_ip2){
            return sort(stat_ip1, stat_ip2);
        });

        std::vector<std::pair<int, double>> loss_rates;
        std::vector<std::pair<int, int>> triggering_probing_rates;

        std::vector<std::pair<int,double>> p_r_r;
        std::vector<std::pair<int,double>> p_u_u;


        for (int i = 0; i < sorted_stats.size(); ++i){
            loss_rates.emplace_back(std::make_pair(i, sorted_stats[i].loss_rate));
            triggering_probing_rates.emplace_back(std::make_pair(i, sorted_stats[i].triggering_probing_rate));
            p_r_r.emplace_back(std::make_pair(i, sorted_stats[i].burst_model.transition(0,0)));
            p_u_u.emplace_back(std::make_pair(i, sorted_stats[i].burst_model.transition(1,1)));
        }

        Gnuplot gp;
        gp << "set terminal pdf\n";
        gp << "set output 'plots/" + plot_infos.title + ".pdf'\n";
        gp << "set multiplot layout 4, 1 title '" +plot_infos.title+ "'\n";
        gp << "plot '-' with points title 'loss\\_rates'\n";
        gp.send1d(loss_rates);
        gp << "plot '-' with points title 'triggering\\_rates'\n";
        gp.send1d(triggering_probing_rates);
        gp << "plot '-' with points title 'P(R,R)'\n";
        gp.send1d(p_r_r);
        gp << "plot '-' with points title 'P(U,U)'\n";
        gp.send1d(p_u_u);

        gp << "unset multiplot\n";
        gp << "unset output\n";

    }

    /**
     * Plot a bitmap representing responsiveness for an ip.
     * @param raw_data
     * @param title
     */
    void plot_bitmap_ip(const std::pair<Tins::IPv4Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> & raw_data, const std::string & title);

    void plot_bitmap_router_rate(const std::unordered_map<Tins::IPv4Address, std::vector<responsive_info_probe_t>> & candidates,
                                 const std::unordered_map<Tins::IPv4Address, std::vector<responsive_info_probe_t>> & witness,
                                 const std::string & title);

    /**
     * Plot a bitmap representing the responsiveness for an alias set and its witnesses.
     *
     * Contract (White): Every candidate and witness must have the same number of rates
     * @param candidates
     * @param witnesses
     * @param title
     */
    void plot_bitmap_router(
            const std::unordered_map<Tins::IPv4Address, std::unordered_map<int, std::vector<rate_limit_plotter_t::responsive_info_probe_t>>> &candidates,
            const std::unordered_map<Tins::IPv4Address, std::unordered_map<int, std::vector<rate_limit_plotter_t::responsive_info_probe_t>>> &witnesses,
            const std::string & title);
    private:
    void plot_bitmap_internal(const std::vector<std::vector<rate_limit_plotter_t::responsive_info_probe_t>> &raw_data,
                                               const std::string &title);
    void plot_bitmap_internal(const std::vector<std::pair<RGBApixel, std::vector<responsive_info_probe_t>>> & raw_data, const std::string & title);
};


#endif //ICMPRATELIMITING_RATE_LIMIT_PLOTTER_T_HPP
