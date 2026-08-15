#include <pwnelf/pattern.hpp>

#include <iostream>

int main(){
    try{
        std::cout << pwnelf::cyclic(5) << std::endl;
    }catch(const std::exception &e){
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}
