//
// Created by System Administrator on 16/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_PLOTTER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_PLOTTER_T_HPP

#include <tins/tins.h>
#include <unordered_map>

#include <EasyBMP.h>
#include <gnuplot-iostream.h>
#include <markov_t.hpp>
#include <utils/struct_utils_t.hpp>
#include <utils/container_utils_t.hpp>
#include <utils/maths_utils_t.hpp>

template<typename IPvAddress>
class rate_limit_plotter_t {
public:

    using probing_rates_t = std::vector<int>;
    using loss_rates_t = std::vector<double>;

    struct plot_infos_t{
        std::string title;
    };

    /**
     * This function plots on the Y axis the loss rates and on the X axis the corresponding probing rates.
     * @param losses
     * @param rates
     */
    void plot_loss_rate_gilbert_eliott(const std::vector<double> &losses,
                                                             const std::vector<int> &rates,
                                                             const std::vector<gilbert_elliot_t> & burst_models) {
        Gnuplot gp;
        // Create a script which can be manually fed into gnuplot later:
        //    Gnuplot gp(">script.gp");
        // Create script and also feed to gnuplot:
        //    Gnuplot gp("tee plot.gp | gnuplot -persist");
        // Or choose any of those options at runtime by setting the GNUPLOT_IOSTREAM_CMD
        // environment variable.

        // Gnuplot vectors (i.e. arrows) require four columns: (x,y,dx,dy)
        std::vector<boost::tuple<double, double, double, double> > pts_A;

        // You can also use a separate container for each column, like so:
        std::vector<double> pts_B_x;
        std::vector<double> pts_B_y;
        std::vector<double> pts_B_dx;
        std::vector<double> pts_B_dy;

        // You could also use:
        //   std::vector<std::vector<double> >
        //   boost::tuple of four std::vector's
        //   std::vector of std::tuple (if you have C++11)
        //   arma::mat (with the Armadillo library)
        //   blitz::Array<blitz::TinyVector<double, 4>, 1> (with the Blitz++ library)
        // ... or anything of that sort

        for(double alpha=0; alpha<1; alpha+=1.0/24.0) {
            double theta = alpha*2.0*3.14159;
            pts_A.push_back(boost::make_tuple(
                    cos(theta),
                    sin(theta),
                    -cos(theta)*0.1,
                    -sin(theta)*0.1
            ));

            pts_B_x .push_back( cos(theta)*0.8);
            pts_B_y .push_back( sin(theta)*0.8);
            pts_B_dx.push_back( sin(theta)*0.1);
            pts_B_dy.push_back(-cos(theta)*0.1);
        }


        std::vector<std::pair<double, double>> loss_rate_by_probing_rate;
        for(int i = 0; i < losses.size(); ++i){
            loss_rate_by_probing_rate.emplace_back(std::make_pair(rates[i], losses[i]));
        }
        std::vector<std::pair<double,double>> p_r_r;
        std::vector<std::pair<double,double>> p_u_u;
        for(int i = 0; i < burst_models.size(); ++i){
            p_r_r.emplace_back(std::make_pair(rates[i], burst_models[i].transition(0, 0)));
            p_u_u.emplace_back(std::make_pair(rates[i], burst_models[i].transition(1,1)));
        }


        // Don't forget to put "\n" at the end of each line!
//    gp << "set xrange [-2:2]\nset yrange [-2:2]\n";
//    // '-' means read from stdin.  The send1d() function sends data to gnuplot's stdin.
//    gp << "plot '-' with vectors title 'pts_A', '-' with vectors title 'pts_B'\n";
//    gp.send1d(pts_A);
//    gp.send1d(boost::make_tuple(pts_B_x, pts_B_y, pts_B_dx, pts_B_dy));
        gp << "plot '-' with lines title 'loss\\_rates', '-' with lines title 'P(R,R)', '-' with lines title 'P(U,U)'\n";

        gp.send1d(loss_rate_by_probing_rate);
        gp.send1d(p_r_r);
        gp.send1d(p_u_u);
    }


    std::stringstream
    dump_loss_rate(const std::unordered_map<IPvAddress, std::unordered_map<int, double>> & loss_rates) {
        std::stringstream stream;
        for (const auto & ip_address_loss_rate : loss_rates){
            stream << ip_address_loss_rate.first.to_string() << "\n";
            for (const auto & rates_loss : ip_address_loss_rate.second){
                stream << "Loss for rate " << rates_loss.first <<": " << rates_loss.second << "\n";
            }
        }
        return stream;
    }
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
    void plot_raw(const std::vector<utils::responsive_info_probe_t> &packets) {
        Gnuplot gp;

        std::vector<std::pair<long long int, int>> responsiveness;

        for (const auto & packet : packets){
//        std::chrono::milliseconds sending_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::microseconds(packet.second.timestamp()));
            std::chrono::microseconds sending_time = std::chrono::microseconds(packet.second.timestamp());
            if (packet.first){
                responsiveness.emplace_back(std::make_pair(sending_time.count(), 1));
            } else {
                responsiveness.emplace_back(std::make_pair(sending_time.count(), 0));
            }
        }
        gp << "plot '-' with points ps 0.5 title 'raw\\_data'\n";
        gp.send1d(responsiveness);
    }


    void plot_bitmap_raw(
            const std::unordered_map<IPvAddress, std::vector<utils::responsive_info_probe_t>> &raw_data, const std::string & title) {

        auto vector_raw = utils::values(raw_data);

        if (raw_data.empty()){
            return;
        }

        plot_bitmap_internal(vector_raw, title);
    }

    template<typename Sort>
    void plot_aggregate(const std::unordered_map<IPvAddress, utils::stats_t> & stats_by_ip, const plot_infos_t & plot_infos,  Sort sort){
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

    void plot_bitmap_ip(
            const std::pair<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &raw_data,
            const std::string &title) {

        auto sorted_vector = utils::values_sorted_by_keys(raw_data.second);


        plot_bitmap_internal(sorted_vector, title);

    }
    void plot_bitmap_router_rate(
            const std::unordered_map<IPvAddress, std::vector<utils::responsive_info_probe_t>> &candidates,
            const std::unordered_map<IPvAddress, std::vector<utils::responsive_info_probe_t>> &witnesses,
            const std::string & title) {

        using namespace utils;
        // Two different colors for witnesses and alias
        auto alias_v = values(candidates);
        auto alias_v_color = add_color(alias_v, black);

        auto witnesses_v = values(witnesses);
        auto witnesses_v_color = add_color(witnesses_v, red);

        decltype(alias_v_color) v;

        std::copy(alias_v_color.begin(), alias_v_color.end(), std::back_inserter(v));
        std::copy(witnesses_v_color.begin(), witnesses_v_color.end(), std::back_inserter(v));

        plot_bitmap_internal(v, title);

    }

    /**
     * Plot a bitmap representing the responsiveness for an alias set and its witnesses.
     *
     * Contract (White): Every candidate and witness must have the same number of rates
     * @param candidates
     * @param witnesses
     * @param title
     */
    void plot_bitmap_router(
            const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &candidates,
            const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &witnesses,
            const std::string &title) {
        using namespace utils;
        auto ip_addresses_candidates = keys(candidates);
        auto ip_addresses_witnesses  = keys(witnesses);

        // Extract the different rates, they must be the same for all candidates and witnesses
        auto rates = keys(candidates.at(ip_addresses_candidates[0]));

        std::sort(rates.begin(), rates.end());

        std::vector<std::pair<RGBApixel, std::vector<responsive_info_probe_t>>> ordered_data;

        for (const auto & rate : rates){

            for (const auto & ip_candidate : ip_addresses_candidates){
                ordered_data.push_back(std::make_pair(black, candidates.at(ip_candidate).at(rate)));
            }

            for (const auto & ip_witness : ip_addresses_witnesses){
                ordered_data.push_back(std::make_pair(red, witnesses.at(ip_witness).at(rate)));
            }
        }

        plot_bitmap_internal(ordered_data, title);

    }




    /**
     *
     * @param candidates
     * @param witnesses
     * @param title
     * @return
     */
    using correlation_matrix_t = std::vector<std::vector<double>>;

    std::vector<std::pair<int, rate_limit_plotter_t::correlation_matrix_t>> compute_correlation_matrix(
            const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &candidates,
            const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &witnesses,
            const std::string &title) {

        using namespace utils;
        auto ip_addresses_candidates = keys(candidates);
        auto ip_addresses_witnesses  = keys(witnesses);
        // Extract the different rates, they must be the same for all candidates and witnesses
        auto rates = keys(candidates.at(ip_addresses_candidates[0]));
        std::sort(rates.begin(), rates.end());


        std::vector<IPvAddress> all_ips (ip_addresses_candidates);
        for (const auto & ip : ip_addresses_witnesses){
            all_ips.push_back(ip);
        }
        auto last_index_candidate = ip_addresses_candidates.size() - 1;

        std::size_t random_variables_n = all_ips.size();




        std::vector<std::pair<int, correlation_matrix_t>> correlation_matrices;

        for (const auto & rate : rates){
            auto correlation_matrix_rate = compute_correlation_matrix(random_variables_n, last_index_candidate, rate, all_ips, candidates, witnesses);
            correlation_matrices.push_back(std::make_pair(rate, correlation_matrix_rate));
        }

        return correlation_matrices;
    }


    void plot_correlation_matrix(
            const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &candidates,
            const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &witnesses,
            const std::string &title) {

        auto correlation_matrices = compute_correlation_matrix(candidates, witnesses, title);
        std::ofstream output_file;
        output_file.open (title);

        for (const auto & matrix : correlation_matrices){
            auto dump_matrix = dump_correlation_matrix(matrix.second, 3);
            output_file << "Rate: " << matrix.first << "\n";
            std::cout << "Rate: " << matrix.first << "\n";
            output_file << dump_matrix << "\n";
            std::cout << dump_matrix << "\n";
        }
        output_file.close();

    }

    double correlation(const std::vector<utils::responsive_info_probe_t> &raw_router_1,
                       const std::vector<utils::responsive_info_probe_t> &raw_router_2) {



        auto responsive_to_binary = [](const utils::responsive_info_probe_t & responsive_info_probe){
            return responsive_info_probe.first ? 1 : 0;
        };

        std::vector<double> X;
        std::transform(raw_router_1.begin(), raw_router_1.end(), std::back_inserter(X), responsive_to_binary);
        std::vector<double> Y;
        std::transform(raw_router_2.begin(), raw_router_2.end(), std::back_inserter(Y), responsive_to_binary);

        auto cor = utils::cov_correlation(X, Y).second;

        return cor;
    }

    private:
    void plot_bitmap_internal(
            const std::vector<std::vector<utils::responsive_info_probe_t>> &raw_data,
            const std::string &title) {

        plot_bitmap_internal(add_color(raw_data, black), title);

    }
    void
    plot_bitmap_internal(const std::vector<std::pair<RGBApixel, std::vector<utils::responsive_info_probe_t>>> &raw_data,
                                               const std::string &title) {


        // Find the maximum width

        auto it = std::max_element(raw_data.begin(), raw_data.end(), [](const auto & raw_data1, const auto & raw_data2){
            return raw_data1.second.size() < raw_data2.second.size();
        });

        int offset = 0;

        std::size_t width_resolution = static_cast<std::size_t >(it->second.size() + offset);

        std::size_t height_resolution = static_cast<std::size_t>(3.0/4 * width_resolution);

        std::size_t limit_height = 4 * raw_data.size();

        if (height_resolution < limit_height) {
            height_resolution = limit_height;
        }
        std::size_t interval_between_line = height_resolution / raw_data.size();


        BMP image;
        image.SetSize(width_resolution, height_resolution);


        // Init the pixels
        for (int i = 0; i < image.TellWidth(); ++i){
            for(int j = 0; j < image.TellHeight(); ++j){
                image.SetPixel(i, j, white);
            }
        }

        // Loop on every two pixel lines.
        for (int i = 0; i < raw_data.size(); ++i){
            for(int j = 0; j < raw_data[i].second.size(); ++j){
//            image.SetPixel(j, i, white);
                if (raw_data[i].second[j].first){
                    for (int k = 0; k < interval_between_line/2; ++k){
                        image.SetPixel( j, interval_between_line*i + k, raw_data[i].first);
                    }
                }
            }
        }
        image.WriteToFile(title.c_str());
    }


    std::string dump_correlation_matrix(const std::vector<std::vector<double>> &matrix, int digit_number) {

        std::stringstream matrix_stream;
        for (int i = 0; i < matrix.size(); ++i){
            matrix_stream << "|";
            for (int j = 0; j < i; ++j){
                for (int k = 0; k <= digit_number+2; ++k){
                    matrix_stream << " ";
                }
                matrix_stream << "|";
            }
            for (int j = i; j < matrix[i].size(); ++j){
                auto cor = matrix[i][j];
                std::string cor_str = std::to_string(cor);
                // Max number of character. One for sign, one for.
                cor_str.resize(digit_number+3);
                matrix_stream << cor_str << "|";
            }
            matrix_stream << "\n";
        }

        return matrix_stream.str();
    }





    std::vector<std::vector<double>> compute_correlation_matrix(std::size_t random_variables_n,
                                                                                      std::size_t last_index_candidate,
                                                                                      int rate,
                                                                                      const std::vector<IPvAddress> & all_ips,
                                                                                      const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &candidates,
                                                                                      const std::unordered_map<IPvAddress, std::unordered_map<int, std::vector<utils::responsive_info_probe_t>>> &witnesses){

        using namespace utils;
        std::vector<std::vector<double>> correlations_matrix(random_variables_n, std::vector<double>(random_variables_n, 0));
        for (int i = 0; i < all_ips.size(); ++i){
            for (int j = i; j <  all_ips.size(); ++j){
                std::vector<responsive_info_probe_t> raw_i;
                std::vector<responsive_info_probe_t> raw_j;
                if (i <= last_index_candidate){
                    raw_i = candidates.at(all_ips[i]).at(rate);
                } else {
                    raw_i = witnesses.at(all_ips[i]).at(rate);
                }

                if (j <= last_index_candidate){
                    raw_j = candidates.at(all_ips[j]).at(rate);
                } else {
                    raw_j = witnesses.at(all_ips[j]).at(rate);
                }
                correlations_matrix[i][j] = correlation(raw_i, raw_j);
            }
        }

        return correlations_matrix;
    }


    std::vector<std::pair<RGBApixel, std::vector<utils::responsive_info_probe_t>>> add_color(const std::vector<std::vector<utils::responsive_info_probe_t>> & sorted_vector,
                                                                                      const RGBApixel & color) const {
        std::vector<std::pair<RGBApixel, std::vector<utils::responsive_info_probe_t>>> raw_data_color;

        for (const auto & raw: sorted_vector){
            raw_data_color.push_back(std::make_pair(color, raw));
        }

        return raw_data_color;
    }

    RGBApixel white {255, 255, 255};
    RGBApixel black {0, 0, 0, 255};
    RGBApixel red   {0, 0, 255, 255};
    // Add the colors

};


#endif //ICMPRATELIMITING_RATE_LIMIT_PLOTTER_T_HPP
