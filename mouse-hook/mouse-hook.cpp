#include "mouse_hk.hpp"
#include <winuser.h>
#include <iostream>

int main()
{
	message_queue_thread queue = message_queue_thread();
    for (;;) 
    {
		std::cout << (key_hk::vk_state(0x41) ? "A Press\n" : "");

		std::cout << (mouse_hk::state(mouse_hk::key_t::mbutton) ? "Middle Mouse Press\n" : "");
		mouse_hk::m_pos pos = mouse_hk::get_pos();
		std::cout << "Mouse X: " << pos.x << " Mouse Y: " << pos.y << std::endl;
	}
}
