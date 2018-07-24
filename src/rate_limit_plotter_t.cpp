//
// Created by System Administrator on 16/07/2018.
//

#include "../include/rate_limit_plotter_t.hpp"
#include "../EasyBMP_1/EasyBMP.h"


void rate_limit_plotter_t::plot_loss_rate_gilbert_eliott(const std::vector<double> &losses,
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

void rate_limit_plotter_t::plot_raw(const std::vector<rate_limit_plotter_t::responsive_info_probe_t> &packets) {
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


void rate_limit_plotter_t::plot_bitmap_raw(
        const std::unordered_map<Tins::IPv4Address, std::vector<rate_limit_plotter_t::responsive_info_probe_t>> &raw_data, const std::string & title) {

    auto vector_raw = values(raw_data);

    if (raw_data.empty()){
        return;
    }

    plot_bitmap_internal(vector_raw, title);

//    // Find the maximum width
//
//    auto it = std::max_element(raw_data.begin(), raw_data.end(), [](const auto & raw_data1, const auto & raw_data2){
//        return raw_data1.second.size() < raw_data2.second.size();
//    });
//
//    int offset = 100;
//
//    std::size_t width_resolution = static_cast<std::size_t >(it->second.size() + offset);
//
//    std::size_t height_resolution = static_cast<std::size_t>(3.0/4 * width_resolution);
//
//    std::size_t limit_height = 4 * raw_data.size();
//
//    if (height_resolution < limit_height) {
//        height_resolution = limit_height;
//    }
//    std::size_t interval_between_line = height_resolution / raw_data.size();
//
//
//    BMP image;
//    image.SetSize(width_resolution, height_resolution);
//    RGBApixel white {255, 255, 255};
//    RGBApixel black {0, 0, 0};
//
//    // Init the pixels
//    for (int i = 0; i < image.TellWidth(); ++i){
//        for(int j = 0; j < image.TellHeight(); ++j){
//            image.SetPixel(i, j, white);
//        }
//    }
//
//    // Loop on every two pixel lines.
//    for (int i = 0; i < vector_raw.size(); ++i){
//        for(int j = 0; j <vector_raw[i].size(); ++j){
////            image.SetPixel(j, i, white);
//            if (vector_raw[i][j].first){
//                for (int k = 0; k < interval_between_line/2; ++k){
//                    image.SetPixel( j, interval_between_line*i + k, black);
//                }
//            }
//        }
//    }
//    image.WriteToFile(title.c_str());
}

void rate_limit_plotter_t::plot_bitmap_ip(
        const std::pair<Tins::IPv4Address, std::unordered_map<int, std::vector<rate_limit_plotter_t::responsive_info_probe_t>>> &raw_data,
        const std::string &title) {

        auto sorted_vector = values_sorted_by_keys(raw_data.second);

        plot_bitmap_internal(sorted_vector, title);

}

void
rate_limit_plotter_t::plot_bitmap_internal(const std::vector<std::vector<rate_limit_plotter_t::responsive_info_probe_t>> &raw_data,
                                           const std::string &title) {


    // Find the maximum width

    auto it = std::max_element(raw_data.begin(), raw_data.end(), [](const auto & raw_data1, const auto & raw_data2){
        return raw_data1.size() < raw_data2.size();
    });

    int offset = 100;

    std::size_t width_resolution = static_cast<std::size_t >(it->size() + offset);

    std::size_t height_resolution = static_cast<std::size_t>(3.0/4 * width_resolution);

    std::size_t limit_height = 4 * raw_data.size();

    if (height_resolution < limit_height) {
        height_resolution = limit_height;
    }
    std::size_t interval_between_line = height_resolution / raw_data.size();


    BMP image;
    image.SetSize(width_resolution, height_resolution);
    RGBApixel white {255, 255, 255};
    RGBApixel black {0, 0, 0, 255};

    // Init the pixels
    for (int i = 0; i < image.TellWidth(); ++i){
        for(int j = 0; j < image.TellHeight(); ++j){
            image.SetPixel(i, j, white);
        }
    }

    // Loop on every two pixel lines.
    for (int i = 0; i < raw_data.size(); ++i){
        for(int j = 0; j < raw_data[i].size(); ++j){
//            image.SetPixel(j, i, white);
            if (raw_data[i][j].first){
                for (int k = 0; k < interval_between_line/2; ++k){
                    image.SetPixel( j, interval_between_line*i + k, black);
                }
            }
        }
    }
    image.WriteToFile(title.c_str());
}
